"""Executable assertions for the standalone tool's present contract."""

from __future__ import annotations

import contextlib
import ctypes
import dataclasses
import errno
import base64
import hashlib
import io
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import typing
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest import mock

PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]
AUDIT_SCRIPT_PATH = PROJECT_DIRECTORY / "check_permissions.py"
sys.path.insert(0, str(PROJECT_DIRECTORY))

import check_permissions as audit_under_test


def run_audit_tool_command(
    *command_arguments: str,
    timeout_seconds: int = 30,
) -> subprocess.CompletedProcess:
    child_environment = os.environ.copy()
    child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [
            sys.executable,
            str(AUDIT_SCRIPT_PATH),
            "--allow-root-audit",
            *map(str, command_arguments),
        ],
        capture_output=True,
        env=child_environment,
        timeout=timeout_seconds,
        check=False,
    )


def current_mount_table() -> audit_under_test.VisibleLinuxMountTable:
    return audit_under_test.VisibleLinuxMountTable(
        audit_under_test.read_current_process_linux_mount_table()
    )


def current_credential_evidence() -> audit_under_test.LinuxProcessCredentialEvidence:
    return audit_under_test.observe_linux_process_credentials()


def permission_auditor(
    *,
    exclusion_rules=(),
    mount_table=None,
    process_credentials=None,
) -> audit_under_test.LinuxFilesystemMutationPermissionAuditor:
    return audit_under_test.LinuxFilesystemMutationPermissionAuditor(
        mount_table or current_mount_table(),
        process_credentials or current_credential_evidence(),
        remain_on_starting_filesystem=False,
        filesystem_types_with_unmodeled_semantics=set(),
        exclusion_rules=exclusion_rules,
        internally_ignored_paths=(),
    )


def assess_one_path(
    path: str,
    selected_capabilities,
    *,
    auditor=None,
) -> audit_under_test.PathCapabilityAssessment:
    active_auditor = auditor or permission_auditor()
    assessments = list(
        active_auditor.assess_path_tree(
            path,
            selected_capabilities=selected_capabilities,
        )
    )
    return assessments[-1]


@contextlib.contextmanager
def inode_attributes_observed_clear():
    clear_evidence = audit_under_test.LinuxInodeAttributeEvidence(
        immutable_attribute_is_set=False,
        append_only_attribute_is_set=False,
        verity_attribute_is_set=False,
    )
    with mock.patch.object(
        audit_under_test,
        "observe_linux_inode_attributes",
        return_value=clear_evidence,
    ):
        yield


def path_assessment_records_from_jsonl(
    output_bytes: bytes,
) -> list[dict]:
    decoded_records = [
        json.loads(line) for line in output_bytes.decode("utf-8").splitlines()
    ]
    return [
        record
        for record in decoded_records
        if record["record_type"] == "filesystem_path_capability_assessment"
    ]


class PermissionInferenceVerificationTests(unittest.TestCase):
    @unittest.skipIf(
        os.geteuid() == 0,
        "mode-bit fixtures require an unprivileged process identity",
    )
    def test_controlled_path_kinds_and_permission_bits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            writable_file = fixture_root / "writable_file"
            read_only_file = fixture_root / "read_only_file"
            locked_directory = fixture_root / "locked_directory"
            regular_file_symbolic_link = fixture_root / "regular_file_symbolic_link"
            missing_target = fixture_root / "missing_target"
            dangling_symbolic_link = fixture_root / "dangling_symbolic_link"
            named_pipe = fixture_root / "named_pipe"

            writable_file.write_bytes(b"writable fixture")
            read_only_file.write_bytes(b"read-only fixture")
            read_only_file.chmod(0o400)
            locked_directory.mkdir(mode=0o500)
            regular_file_symbolic_link.symlink_to(writable_file)
            dangling_symbolic_link.symlink_to(missing_target)
            os.mkfifo(named_pipe, 0o600)

            try:
                with inode_attributes_observed_clear():
                    writable_assessment = assess_one_path(
                        str(writable_file),
                        audit_under_test.CAPABILITY_EVALUATION_ORDER,
                    )
                    self.assertEqual(
                        writable_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT
                        ).model_verdict,
                        audit_under_test.MODEL_VERDICT_INDICATES_ALLOWED,
                    )
                    self.assertEqual(
                        writable_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT
                        ).model_verdict,
                        audit_under_test.MODEL_VERDICT_INDICATES_ALLOWED,
                    )

                    read_only_assessment = assess_one_path(
                        str(read_only_file),
                        audit_under_test.CAPABILITY_EVALUATION_ORDER,
                    )
                    read_only_append_inference = (
                        read_only_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT
                        )
                    )
                    self.assertEqual(
                        read_only_append_inference.model_verdict,
                        audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                    )
                    self.assertIn(
                        "target_write_access_may_be_changeable_by_chmod",
                        {
                            reason.reason_code
                            for reason in read_only_append_inference.evidence_reasons
                        },
                    )
                    self.assertEqual(
                        read_only_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
                        ).model_verdict,
                        audit_under_test.MODEL_VERDICT_INDICATES_ALLOWED,
                    )

                    locked_assessment = assess_one_path(
                        str(locked_directory),
                        (audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY,),
                    )
                    self.assertEqual(
                        locked_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY
                        ).model_verdict,
                        audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                    )

                    symbolic_link_assessment = assess_one_path(
                        str(regular_file_symbolic_link),
                        audit_under_test.CAPABILITY_EVALUATION_ORDER,
                    )
                    self.assertEqual(
                        symbolic_link_assessment.filesystem_object_kind,
                        audit_under_test.FILESYSTEM_OBJECT_KIND_SYMBOLIC_LINK,
                    )
                    self.assertEqual(
                        symbolic_link_assessment.resolved_symbolic_link_target_kind,
                        audit_under_test.FILESYSTEM_OBJECT_KIND_REGULAR_FILE,
                    )
                    self.assertEqual(
                        symbolic_link_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT
                        ).model_verdict,
                        audit_under_test.MODEL_VERDICT_INDICATES_ALLOWED,
                    )

                    dangling_assessment = assess_one_path(
                        str(dangling_symbolic_link),
                        audit_under_test.CAPABILITY_EVALUATION_ORDER,
                    )
                    self.assertEqual(
                        dangling_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY
                        ).model_verdict,
                        audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED,
                    )

                    named_pipe_assessment = assess_one_path(
                        str(named_pipe),
                        (audit_under_test.CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION,),
                    )
                    self.assertEqual(
                        named_pipe_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION
                        ).model_verdict,
                        audit_under_test.MODEL_VERDICT_INDICATES_ALLOWED,
                    )
            finally:
                locked_directory.chmod(0o700)

    def test_capabilities_are_selected_directly_and_canonically(self) -> None:
        default_configuration = audit_under_test.parse_audit_command_line_arguments(
            ["/explicit"]
        )
        self.assertEqual(
            default_configuration.selected_capabilities,
            audit_under_test.DEFAULT_MUTATION_CAPABILITIES,
        )

        explicit_configuration = audit_under_test.parse_audit_command_line_arguments(
            [
                "--capability",
                audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY,
                "--capability",
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                "--capability",
                audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY,
                "/explicit",
            ]
        )
        self.assertEqual(
            explicit_configuration.selected_capabilities,
            (
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY,
            ),
        )

    def test_multiple_leading_separators_name_one_linux_root(self) -> None:
        for reported_path, expected_normalized_path in (
            ("//", "/"),
            ("///", "/"),
            ("//var///tmp/", "/var/tmp"),
        ):
            with self.subTest(reported_path=reported_path):
                self.assertEqual(
                    audit_under_test.lexically_normalize_absolute_path(reported_path),
                    expected_normalized_path,
                )

    def test_symlink_then_dot_dot_uses_kernel_component_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            lexical_parent = fixture_root / "lexical"
            physical_parent = fixture_root / "physical"
            lexical_parent.mkdir()
            (physical_parent / "through-link").mkdir(parents=True)
            kernel_selected_directory = physical_parent / "selected"
            kernel_selected_directory.mkdir()
            lexically_selected_directory = lexical_parent / "selected"
            lexically_selected_directory.mkdir()
            (lexical_parent / "link").symlink_to(physical_parent / "through-link")
            requested_path = lexical_parent / "link" / ".." / "selected"

            assessment = assess_one_path(
                str(requested_path),
                (audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY,),
            )

        self.assertEqual(assessment.audited_path, str(kernel_selected_directory))
        self.assertNotEqual(assessment.audited_path, str(lexically_selected_directory))

    def test_trailing_separator_retains_kernel_directory_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            regular_file = Path(temporary_directory) / "regular-file"
            regular_file.write_bytes(b"content")

            assessment = assess_one_path(
                str(regular_file) + "/",
                audit_under_test.DEFAULT_MUTATION_CAPABILITIES,
            )

        self.assertEqual(
            assessment.filesystem_object_kind,
            audit_under_test.FILESYSTEM_OBJECT_KIND_UNOBSERVED,
        )
        self.assertEqual(
            {
                inference.model_verdict
                for inference in assessment.inference_by_capability_name.values()
            },
            {audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED},
        )
        self.assertEqual(
            next(iter(assessment.inference_by_capability_name.values()))
            .evidence_reasons[0]
            .reason_code,
            "requested_path_component_is_not_a_directory",
        )

    def test_trailing_separator_symlink_is_not_misclassified_as_target_tree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            target_directory = fixture_root / "target"
            target_directory.mkdir()
            (target_directory / "descendant").write_bytes(b"descendant")
            symbolic_link = fixture_root / "link"
            symbolic_link.symlink_to(target_directory.name)

            with inode_attributes_observed_clear():
                assessments = list(
                    permission_auditor().assess_path_tree(
                        str(symbolic_link) + "/",
                        selected_capabilities=(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                            audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY,
                        ),
                    )
                )

        self.assertEqual(len(assessments), 1)
        assessment = assessments[0]
        self.assertEqual(
            assessment.filesystem_object_kind,
            audit_under_test.FILESYSTEM_OBJECT_KIND_SYMBOLIC_LINK,
        )
        self.assertEqual(
            assessment.resolved_symbolic_link_target_kind,
            audit_under_test.FILESYSTEM_OBJECT_KIND_DIRECTORY,
        )
        delete_inference = assessment.inference_for_capability(
            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
        )
        self.assertEqual(
            delete_inference.model_verdict,
            audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED,
        )
        self.assertEqual(
            {reason.reason_code for reason in delete_inference.evidence_reasons},
            {
                "requested_trailing_separator_forces_final_symbolic_link_following"
            },
        )

    def test_trailing_separator_symlink_target_swap_makes_following_inference_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            target = fixture_root / "target"
            target.mkdir()
            symbolic_link = fixture_root / "link"
            symbolic_link.symlink_to(target.name)
            active_auditor = permission_auditor()
            assess_normally = active_auditor.assess_non_directory_path

            def replace_target_then_assess(*args, **kwargs):
                target.rmdir()
                target.write_bytes(b"replacement")
                return assess_normally(*args, **kwargs)

            with mock.patch.object(
                active_auditor,
                "assess_non_directory_path",
                side_effect=replace_target_then_assess,
            ):
                assessment = assess_one_path(
                    str(symbolic_link) + "/",
                    (
                        audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                        audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                    ),
                    auditor=active_auditor,
                )

        self.assertEqual(
            assessment.inference_for_capability(
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
            ).model_verdict,
            audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED,
        )
        append_inference = assessment.inference_for_capability(
            audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT
        )
        self.assertEqual(
            append_inference.model_verdict,
            audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
        )
        self.assertIn(
            "trailing_separator_symbolic_link_target_changed_during_assessment",
            {reason.reason_code for reason in append_inference.evidence_reasons},
        )

    def test_trailing_separator_exclusion_matches_symlink_not_target_tree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            target = fixture_root / "target"
            target.mkdir()
            symbolic_link = fixture_root / "link"
            symbolic_link.symlink_to(target.name)
            exclusion_rule = audit_under_test.path_exclusion_rule_from_user_argument(
                str(symbolic_link) + "/"
            )
            assessment = assess_one_path(
                str(symbolic_link) + "/",
                (audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,),
                auditor=permission_auditor(exclusion_rules=(exclusion_rule,)),
            )

        self.assertEqual(exclusion_rule.excluded_path, str(symbolic_link))
        self.assertFalse(exclusion_rule.includes_descendants)
        self.assertEqual(
            assessment.inference_for_capability(
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
            ).model_verdict,
            audit_under_test.MODEL_VERDICT_SKIPPED,
        )

    def test_requested_missing_name_is_revalidated_after_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            missing_path = Path(temporary_directory) / "initially-missing"
            active_auditor = permission_auditor()
            assess_missing_normally = (
                active_auditor.assess_explicitly_requested_missing_path
            )

            def assess_then_create_name(*args, **kwargs):
                assessment = assess_missing_normally(*args, **kwargs)
                missing_path.write_bytes(b"appeared")
                return assessment

            with mock.patch.object(
                active_auditor,
                "assess_explicitly_requested_missing_path",
                side_effect=assess_then_create_name,
            ):
                assessment = assess_one_path(
                    str(missing_path),
                    (audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY,),
                    auditor=active_auditor,
                )

        create_inference = assessment.inference_for_capability(
            audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY
        )
        self.assertEqual(
            create_inference.model_verdict,
            audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
        )
        self.assertIn(
            "requested_missing_path_appeared_during_assessment",
            {reason.reason_code for reason in create_inference.evidence_reasons},
        )

    def test_explicit_uncertain_filesystem_type_augments_defaults(self) -> None:
        configuration = audit_under_test.parse_audit_command_line_arguments(
            [
                "--uncertain-filesystem-type",
                "customfs",
                "/explicit",
            ]
        )
        self.assertEqual(
            audit_under_test.uncertain_filesystem_types_for_configuration(configuration)
            - audit_under_test.FILESYSTEM_TYPES_WITH_UNMODELED_MUTATION_SEMANTICS,
            {"customfs"},
        )

    def test_dangling_symbolic_link_is_not_a_creation_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            dangling_symbolic_link = Path(temporary_directory) / "dangling-link"
            dangling_symbolic_link.symlink_to("missing-target")

            assessment = assess_one_path(
                str(dangling_symbolic_link),
                (audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY,),
            )

        create_inference = assessment.inference_for_capability(
            audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY
        )
        self.assertEqual(
            create_inference.model_verdict,
            audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED,
        )
        self.assertEqual(
            create_inference.evidence_reasons[0].reason_code,
            "symbolic_link_with_missing_target_cannot_create_a_child_entry",
        )

    def test_delete_only_symbolic_link_audit_does_not_observe_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            target_path = fixture_root / "target"
            target_path.write_bytes(b"target")
            symbolic_link_path = fixture_root / "symbolic-link"
            symbolic_link_path.symlink_to(target_path.name)
            active_auditor = permission_auditor()
            real_stat = audit_under_test.os.stat

            with (
                mock.patch.object(
                    active_auditor,
                    "_observe_symbolic_link_target_path",
                ) as target_path_observation,
                mock.patch.object(
                    audit_under_test.os,
                    "stat",
                    wraps=real_stat,
                ) as stat_observation,
                inode_attributes_observed_clear(),
            ):
                assessment = assess_one_path(
                    str(symbolic_link_path),
                    (audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,),
                    auditor=active_auditor,
                )

        target_path_observation.assert_not_called()
        self.assertNotIn(
            mock.call(str(symbolic_link_path)),
            stat_observation.call_args_list,
        )
        self.assertIsNone(assessment.resolved_symbolic_link_target_path)
        self.assertIsNone(assessment.resolved_symbolic_link_target_kind)

    def test_postorder_delete_aggregation_preserves_path_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            child_directory = fixture_root / "child_directory"
            child_directory.mkdir()
            leaf_file = child_directory / "leaf_file"
            leaf_file.write_bytes(b"leaf")

            with inode_attributes_observed_clear():
                assessments = list(
                    permission_auditor().assess_path_tree(
                        str(fixture_root),
                        selected_capabilities=(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                        ),
                    )
                )

            self.assertEqual(
                [assessment.audited_path for assessment in assessments],
                [
                    str(leaf_file),
                    str(child_directory),
                    str(fixture_root),
                ],
            )

    def test_known_blocked_child_outweighs_partial_listing_uncertainty(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            active_auditor = permission_auditor()
            with inode_attributes_observed_clear():
                root_assessment = active_auditor.assess_directory(
                    str(fixture_root),
                    os.lstat(fixture_root),
                    (audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,),
                    has_uncertain_descendant_delete=False,
                    has_blocked_descendant_delete=True,
                    directory_listing_failure=audit_under_test.EvidenceReason(
                        "simulated_partial_directory_read",
                        evidence_source="test",
                    ),
                    observation_notes=(),
                    directory_identity_matched_lstat=True,
                )

            root_delete_inference = root_assessment.inference_for_capability(
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
            )
            self.assertEqual(
                root_delete_inference.model_verdict,
                audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED,
            )
            self.assertIn(
                "at_least_one_descendant_would_remain",
                {
                    reason.reason_code
                    for reason in root_delete_inference.evidence_reasons
                },
            )


class AuditScopeDiscoveryEvidenceTests(unittest.TestCase):
    def test_home_candidates_name_source_normalization_and_disposition(
        self,
    ) -> None:
        passwd_home_by_user_id = {
            1200: "/people/shared-home",
            3400: "/",
        }

        def passwd_record_for_user_id(user_id: int):
            return mock.Mock(pw_dir=passwd_home_by_user_id[user_id])

        process_credentials = mock.Mock(
            real_user_id=1200,
            effective_user_id=3400,
        )
        with (
            mock.patch.dict(
                audit_under_test.os.environ,
                {
                    "HOME": "/people/shared-home",
                    "SUDO_USER": "invoking-user",
                },
                clear=True,
            ),
            mock.patch.object(
                audit_under_test.pwd,
                "getpwuid",
                side_effect=passwd_record_for_user_id,
            ),
            mock.patch.object(
                audit_under_test.pwd,
                "getpwnam",
                return_value=mock.Mock(pw_dir="/people/invoking-home"),
            ),
            mock.patch.object(
                audit_under_test,
                "observe_canonical_existing_directory",
                side_effect=lambda path, **_kwargs: (
                    audit_under_test.lexically_normalize_absolute_path(path),
                    None,
                ),
            ),
        ):
            discovery = audit_under_test.discover_process_related_home_directories(
                process_credentials
            )

        self.assertEqual(
            discovery.accepted_home_directory_exclusion_paths,
            (
                "/people/shared-home",
                "/people/invoking-home",
            ),
        )
        observations_by_normalized_path = {
            observation.normalized_home_directory_path: observation
            for observation in discovery.candidate_observations
        }
        shared_home_observation = observations_by_normalized_path["/people/shared-home"]
        self.assertIn(
            "HOME environment variable",
            shared_home_observation.candidate_source,
        )
        self.assertIn(
            "process_credential_roles=real_user_id",
            shared_home_observation.candidate_source,
        )
        self.assertEqual(
            shared_home_observation.candidate_disposition,
            audit_under_test.HOME_DIRECTORY_CANDIDATE_ACCEPTED_FOR_DEFAULT_EXCLUSION,
        )
        self.assertEqual(
            observations_by_normalized_path["/"].candidate_disposition,
            audit_under_test.HOME_DIRECTORY_CANDIDATE_REJECTED_AS_FILESYSTEM_ROOT,
        )
        self.assertEqual(discovery.uncertainty_reasons, ())
        self.assertTrue(discovery.observed_at_utc.endswith("Z"))

    def test_home_candidate_dot_dot_after_symlink_uses_kernel_resolution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            lexical_parent = fixture_root / "lexical"
            physical_parent = fixture_root / "physical"
            lexical_parent.mkdir()
            (physical_parent / "through-link").mkdir(parents=True)
            kernel_home = physical_parent / "home"
            lexical_home = lexical_parent / "home"
            kernel_home.mkdir()
            lexical_home.mkdir()
            (lexical_parent / "link").symlink_to(physical_parent / "through-link")
            requested_home = lexical_parent / "link" / ".." / "home"
            process_credentials = mock.Mock(
                real_user_id=1200,
                effective_user_id=1200,
            )

            with (
                mock.patch.dict(
                    audit_under_test.os.environ,
                    {"HOME": str(requested_home)},
                    clear=True,
                ),
                mock.patch.object(
                    audit_under_test.pwd,
                    "getpwuid",
                    return_value=mock.Mock(pw_dir=str(requested_home)),
                ),
            ):
                discovery = audit_under_test.discover_process_related_home_directories(
                    process_credentials
                )

        self.assertEqual(
            discovery.accepted_home_directory_exclusion_paths,
            (str(kernel_home),),
        )
        self.assertNotIn(
            str(lexical_home),
            discovery.accepted_home_directory_exclusion_paths,
        )
        self.assertEqual(discovery.uncertainty_reasons, ())

    def test_temporary_directory_candidates_name_every_current_decision(
        self,
    ) -> None:
        process_credentials = mock.Mock()

        def candidate_metadata(candidate_path: str):
            if candidate_path == "/reported-regular-file":
                return mock.Mock(st_mode=stat.S_IFREG | 0o600)
            if candidate_path == "/selected-temporary-directory":
                return mock.Mock(st_mode=stat.S_IFDIR | 0o700)
            self.fail(f"unexpected candidate observation: {candidate_path}")

        with (
            mock.patch.dict(
                audit_under_test.os.environ,
                {
                    "TMPDIR": "/reported-regular-file",
                    "TEMP": "/selected-temporary-directory",
                    "TMP": "/selected-temporary-directory",
                },
                clear=True,
            ),
            mock.patch.object(
                audit_under_test.os,
                "stat",
                side_effect=candidate_metadata,
            ),
            mock.patch.object(
                audit_under_test,
                "ask_kernel_about_path_access",
                return_value=audit_under_test.KernelPathAccessEvidence(
                    access_is_allowed=True,
                    uncertainty_reason=None,
                ),
            ) as access_observation,
            mock.patch.object(
                audit_under_test,
                "observe_canonical_existing_directory",
                side_effect=lambda path, **_kwargs: (
                    audit_under_test.lexically_normalize_absolute_path(path),
                    None,
                ),
            ),
        ):
            discovery = audit_under_test.discover_active_writable_temporary_directory(
                process_credentials
            )

        self.assertEqual(
            discovery.selected_writable_temporary_directory,
            "/selected-temporary-directory",
        )
        self.assertEqual(
            discovery.normalized_candidate_paths,
            (
                "/reported-regular-file",
                "/selected-temporary-directory",
            ),
        )
        self.assertEqual(
            [
                observation.reason_code
                for observation in discovery.candidate_observations
            ],
            [
                "temporary_directory_candidate_is_not_a_directory",
                "temporary_directory_candidate_was_selected",
            ],
        )
        self.assertIn(
            "TEMP environment variable, TMP environment variable",
            discovery.candidate_observations[-1].evidence_source,
        )
        access_observation.assert_called_once_with(
            "/selected-temporary-directory",
            os.W_OK | os.X_OK,
            process_credentials=process_credentials,
        )
        self.assertEqual(discovery.uncertainty_reasons, ())
        self.assertTrue(discovery.observed_at_utc.endswith("Z"))


class SafeOptimizationVerificationTests(unittest.TestCase):
    def test_strict_realpath_avoids_path_object_on_supported_python(self) -> None:
        with (
            mock.patch.object(
                audit_under_test,
                "_OS_PATH_REALPATH_SUPPORTS_STRICT",
                True,
            ),
            mock.patch.object(
                audit_under_test.os.path,
                "realpath",
                return_value="/resolved/path",
            ) as realpath,
        ):
            resolved_path = audit_under_test.strictly_resolve_path("/input/path")

        self.assertEqual(resolved_path, "/resolved/path")
        realpath.assert_called_once_with("/input/path", strict=True)

    def test_strict_realpath_retains_python_39_pathlib_fallback(self) -> None:
        with (
            mock.patch.object(
                audit_under_test,
                "_OS_PATH_REALPATH_SUPPORTS_STRICT",
                False,
            ),
            mock.patch.object(
                audit_under_test.Path,
                "resolve",
                return_value=audit_under_test.Path("/fallback/path"),
            ) as pathlib_resolve,
        ):
            resolved_path = audit_under_test.strictly_resolve_path("/input/path")

        self.assertEqual(resolved_path, "/fallback/path")
        pathlib_resolve.assert_called_once_with(strict=True)

    def test_ordinary_terminal_path_bypasses_character_encoder(self) -> None:
        with mock.patch(
            "builtins.ord",
            side_effect=AssertionError("ordinary path used character encoder"),
        ):
            escaped_path = audit_under_test.escape_linux_path_text_for_terminal(
                "/ordinary/printable-path_123"
            )

        self.assertEqual(escaped_path, "/ordinary/printable-path_123")
        self.assertEqual(
            audit_under_test.escape_linux_path_text_for_terminal(
                'quote" backslash\\ newline\n byte\udcff delete\x7f'
            ),
            'quote\\" backslash\\\\ newline\\n byte\\xff delete\\u007f',
        )

    def test_parent_resolution_is_reused_only_within_one_assessment(self) -> None:
        active_auditor = permission_auditor()

        with mock.patch.object(
            audit_under_test,
            "strictly_resolve_path",
            wraps=audit_under_test.strictly_resolve_path,
        ) as strict_resolution:
            first_assessment_cache = audit_under_test.PathAssessmentEvidenceCache()
            active_auditor._lookup_mount_within_path_assessment(
                "/tmp/nonexistent-audit-target",
                follow_final_symbolic_link=False,
                evidence_cache=first_assessment_cache,
            )
            active_auditor._lookup_mount_within_path_assessment(
                "/tmp",
                follow_final_symbolic_link=True,
                evidence_cache=first_assessment_cache,
            )
            self.assertEqual(strict_resolution.call_count, 1)

            active_auditor._lookup_mount_within_path_assessment(
                "/tmp/nonexistent-audit-target",
                follow_final_symbolic_link=False,
                evidence_cache=audit_under_test.PathAssessmentEvidenceCache(),
            )

        self.assertEqual(strict_resolution.call_count, 2)

    def test_reused_resolution_failure_keeps_context_specific_reason(self) -> None:
        resolution_cache: dict[
            str,
            audit_under_test.StrictPathResolutionObservation,
        ] = {}
        denied_error = OSError(errno.EACCES, os.strerror(errno.EACCES), "/blocked")

        with mock.patch.object(
            audit_under_test,
            "strictly_resolve_path",
            side_effect=denied_error,
        ) as strict_resolution:
            _, parent_reason = (
                audit_under_test.best_effort_resolve_parent_components_only(
                    "/blocked/entry",
                    resolution_cache=resolution_cache,
                )
            )
            _, path_reason = audit_under_test.best_effort_resolve_existing_path(
                "/blocked",
                resolution_cache=resolution_cache,
            )

        strict_resolution.assert_called_once_with("/blocked")
        self.assertIsNotNone(parent_reason)
        self.assertIsNotNone(path_reason)
        assert parent_reason is not None
        assert path_reason is not None
        self.assertEqual(
            parent_reason.reason_code,
            "cannot_resolve_parent_for_mountpoint_lookup",
        )
        self.assertEqual(
            path_reason.reason_code,
            "cannot_resolve_path_for_mount_lookup",
        )
        self.assertEqual(parent_reason.operating_system_errno, errno.EACCES)
        self.assertEqual(path_reason.operating_system_errno, errno.EACCES)

    def test_identical_evidence_is_reused_only_within_one_path_assessment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_file = Path(temporary_directory) / "audited-file"
            audited_file.write_bytes(b"content")
            audited_file_metadata = os.lstat(audited_file)
            active_auditor = permission_auditor()

            with (
                mock.patch.object(
                    active_auditor.mount_table,
                    "lookup_mount_for_path",
                    wraps=active_auditor.mount_table.lookup_mount_for_path,
                ) as mount_lookup,
                mock.patch.object(
                    audit_under_test,
                    "observe_linux_inode_attributes",
                    wraps=audit_under_test.observe_linux_inode_attributes,
                ) as inode_attribute_observation,
                mock.patch.object(
                    active_auditor,
                    "ask_kernel_about_access",
                    wraps=active_auditor.ask_kernel_about_access,
                ) as access_observation,
            ):
                first_assessment = active_auditor.assess_non_directory_path(
                    str(audited_file),
                    audited_file_metadata,
                    audit_under_test.FILESYSTEM_OBJECT_KIND_REGULAR_FILE,
                    audit_under_test.DEFAULT_MUTATION_CAPABILITIES,
                )

                self.assertEqual(mount_lookup.call_count, 3)
                self.assertEqual(inode_attribute_observation.call_count, 3)
                self.assertEqual(access_observation.call_count, 2)
                self.assertEqual(
                    {
                        first_assessment.inference_for_capability(
                            capability_name
                        ).model_verdict
                        for capability_name in (
                            audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                            audit_under_test.CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT,
                        )
                    },
                    {audit_under_test.MODEL_VERDICT_INDICATES_ALLOWED},
                )

                active_auditor.assess_non_directory_path(
                    str(audited_file),
                    audited_file_metadata,
                    audit_under_test.FILESYSTEM_OBJECT_KIND_REGULAR_FILE,
                    audit_under_test.DEFAULT_MUTATION_CAPABILITIES,
                )

            self.assertEqual(mount_lookup.call_count, 6)
            self.assertEqual(inode_attribute_observation.call_count, 6)
            self.assertEqual(access_observation.call_count, 4)

    def test_combined_write_search_denial_is_split_for_precise_reasons(
        self,
    ) -> None:
        active_auditor = permission_auditor()
        allowed = audit_under_test.KernelPathAccessEvidence(True, None)
        blocked = audit_under_test.KernelPathAccessEvidence(False, None)

        def access_evidence_for_mode(
            _path: str,
            requested_access_mode: int,
        ) -> audit_under_test.KernelPathAccessEvidence:
            return allowed if requested_access_mode == os.X_OK else blocked

        with mock.patch.object(
            active_auditor,
            "ask_kernel_about_access",
            side_effect=access_evidence_for_mode,
        ) as access_observation:
            write_access, search_access = (
                active_auditor._ask_kernel_about_write_and_search_within_path_assessment(
                    "/modeled-directory",
                    evidence_cache=audit_under_test.PathAssessmentEvidenceCache(),
                )
            )

        self.assertFalse(write_access.access_is_allowed)
        self.assertTrue(search_access.access_is_allowed)
        self.assertEqual(
            access_observation.call_args_list,
            [
                mock.call("/modeled-directory", os.W_OK | os.X_OK),
                mock.call("/modeled-directory", os.W_OK),
                mock.call("/modeled-directory", os.X_OK),
            ],
        )

    def test_lexical_mount_walk_does_not_renormalize_each_ancestor(self) -> None:
        root_mount = mock.sentinel.root_mount
        nested_mount = mock.sentinel.nested_mount
        mount_table = object.__new__(audit_under_test.VisibleLinuxMountTable)
        mount_table.visible_root_mount = root_mount
        mount_table.visible_mount_by_mountpoint = {
            "/": root_mount,
            "/nested": nested_mount,
        }

        with mock.patch.object(
            audit_under_test,
            "lexically_normalize_absolute_path",
            side_effect=AssertionError("hot mount walk renormalized an ancestor"),
        ):
            observed_mount = mount_table._visible_mount_for_lexical_path(
                "/nested/one/two"
            )

        self.assertIs(observed_mount, nested_mount)

    def test_nonmatching_assessment_is_filtered_before_record_allocation(
        self,
    ) -> None:
        configuration = audit_under_test.parse_audit_command_line_arguments(("/scope",))
        blocked_inference = audit_under_test.capability_inference(
            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
            audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED,
        )
        assessment = mock.Mock()
        assessment.inference_for_capability.return_value = blocked_inference
        permission_model = mock.Mock()
        permission_model.assess_path_tree.return_value = iter((assessment,))

        emitted_records = list(
            audit_under_test.iterate_structured_path_audit_records(
                configuration,
                permission_model,
            )
        )

        self.assertEqual(emitted_records, [])
        assessment.create_structured_record.assert_not_called()

    def test_allowed_path_still_counts_an_uncertain_selected_capability(self) -> None:
        configuration = audit_under_test.parse_audit_command_line_arguments(
            (
                "--capability",
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                "--capability",
                audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                "/scope",
            )
        )
        assessment = audit_under_test.PathCapabilityAssessment(
            filesystem_object_kind=(
                audit_under_test.FILESYSTEM_OBJECT_KIND_REGULAR_FILE
            ),
            audited_path="/scope",
            inference_by_capability_name={
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE: (
                    audit_under_test.capability_inference(
                        audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                        audit_under_test.MODEL_VERDICT_INDICATES_ALLOWED,
                    )
                ),
                audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT: (
                    audit_under_test.capability_inference(
                        audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                        audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                    )
                ),
            },
        )
        permission_model = mock.Mock()
        permission_model.assess_path_tree.return_value = iter((assessment,))
        statistics = audit_under_test.AuditRunStatistics()

        emitted_records = list(
            audit_under_test.iterate_structured_path_audit_records(
                configuration,
                permission_model,
                statistics=statistics,
            )
        )

        self.assertEqual(len(emitted_records), 1)
        self.assertEqual(statistics.allowed_path_count, 1)
        self.assertEqual(statistics.uncertain_path_count, 0)
        self.assertEqual(
            statistics.selected_capability_uncertainty_path_count,
            1,
        )
        self.assertTrue(statistics.uncertainty_was_observed)


class EvidenceUncertaintyVerificationTests(unittest.TestCase):
    def test_raw_syscall_map_rejects_kernel_process_abi_width_mismatch(
        self,
    ) -> None:
        with (
            mock.patch.object(
                audit_under_test,
                "RUNNING_MACHINE_ARCHITECTURE",
                "aarch64",
            ),
            mock.patch.object(
                audit_under_test.ctypes,
                "sizeof",
                return_value=4,
            ),
        ):
            self.assertIsNone(audit_under_test.linux_syscall_number("statx"))

        with mock.patch.object(
            audit_under_test,
            "RUNNING_MACHINE_ARCHITECTURE",
            "arm",
        ):
            self.assertIsNone(audit_under_test.linux_syscall_number("statx"))

    def test_statx_structure_layout_matches_every_field_the_auditor_reads(
        self,
    ) -> None:
        self.assertEqual(
            ctypes.sizeof(audit_under_test.LinuxStatxStructure),
            audit_under_test.LINUX_STATX_STRUCTURE_SIZE_BYTES,
        )
        self.assertEqual(
            audit_under_test.LinuxStatxStructure.stx_attributes.offset,
            audit_under_test.LINUX_STATX_ATTRIBUTES_OFFSET_BYTES,
        )
        self.assertEqual(
            audit_under_test.LinuxStatxStructure.stx_attributes_mask.offset,
            audit_under_test.LINUX_STATX_ATTRIBUTES_MASK_OFFSET_BYTES,
        )

    def test_statx_uses_raw_syscall_when_libc_wrapper_is_missing(self) -> None:
        if audit_under_test.linux_syscall_number("statx") is None:
            self.skipTest("test process ABI has no verified statx syscall mapping")
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_file = Path(temporary_directory) / "file"
            audited_file.write_bytes(b"content")
            with mock.patch.object(
                audit_under_test,
                "_LINUX_STATX_FUNCTION",
                None,
            ):
                evidence = audit_under_test.observe_linux_inode_attributes(
                    str(audited_file),
                    follow_final_symbolic_link=True,
                )

        self.assertNotIn(
            "linux_statx_unavailable_for_process_abi",
            {reason.reason_code for reason in evidence.uncertainty_reasons},
        )
        self.assertIsInstance(evidence.immutable_attribute_is_set, bool)
        self.assertIsInstance(evidence.append_only_attribute_is_set, bool)

    def test_access_query_preserves_denial_and_failure_errno(self) -> None:
        process_credentials = current_credential_evidence()

        def failed_access_with_errno(error_number):
            def fail(*_args):
                ctypes.set_errno(error_number)
                return -1

            return fail

        with mock.patch.object(
            audit_under_test,
            "call_linux_faccessat2",
            side_effect=failed_access_with_errno(errno.EACCES),
        ):
            denied = audit_under_test.ask_kernel_about_path_access(
                "/modeled",
                os.W_OK,
                process_credentials=process_credentials,
            )
        with mock.patch.object(
            audit_under_test,
            "call_linux_faccessat2",
            side_effect=failed_access_with_errno(errno.EIO),
        ):
            failed = audit_under_test.ask_kernel_about_path_access(
                "/modeled",
                os.W_OK,
                process_credentials=process_credentials,
            )

        self.assertFalse(denied.access_is_allowed)
        self.assertEqual(denied.operating_system_errno, errno.EACCES)
        self.assertIsNone(failed.access_is_allowed)
        self.assertEqual(failed.operating_system_errno, errno.EIO)
        self.assertEqual(
            failed.uncertainty_reason.reason_code,
            "effective_id_access_check_failed",
        )

    def test_pre_faccessat2_kernel_fallback_is_acl_correct_for_matching_ids(
        self,
    ) -> None:
        if audit_under_test._LINUX_FACCESSAT_FUNCTION is None:
            self.skipTest("libc does not expose faccessat")
        process_credentials = current_credential_evidence()
        if (
            process_credentials.real_user_id != process_credentials.effective_user_id
            or process_credentials.real_group_id
            != process_credentials.effective_group_id
            or process_credentials.effective_user_id == 0
            or process_credentials.effective_capabilities.capability_mask != 0
        ):
            self.skipTest(
                "test process identity does not permit the safe faccessat fallback"
            )
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_file = Path(temporary_directory) / "file"
            audited_file.write_bytes(b"content")

            def unavailable_faccessat2(*_args):
                ctypes.set_errno(errno.ENOSYS)
                return -1

            with mock.patch.object(
                audit_under_test,
                "call_linux_faccessat2",
                side_effect=unavailable_faccessat2,
            ):
                evidence = audit_under_test.ask_kernel_about_path_access(
                    str(audited_file),
                    os.R_OK,
                    process_credentials=process_credentials,
                )

        self.assertTrue(evidence.access_is_allowed)
        self.assertIn("matching real/effective", evidence.evidence_source)

    def test_pre_faccessat2_fallback_rejects_non_equivalent_capability_semantics(
        self,
    ) -> None:
        current_credentials = current_credential_evidence()

        def unavailable_faccessat2(*_args):
            ctypes.set_errno(errno.ENOSYS)
            return -1

        for effective_user_id, effective_capability_mask in ((0, 0), (1000, 1)):
            with self.subTest(
                effective_user_id=effective_user_id,
                effective_capability_mask=effective_capability_mask,
            ):
                process_credentials = replace(
                    current_credentials,
                    real_user_id=effective_user_id,
                    effective_user_id=effective_user_id,
                    real_group_id=1000,
                    effective_group_id=1000,
                    filesystem_identifiers=replace(
                        current_credentials.filesystem_identifiers,
                        filesystem_user_id=effective_user_id,
                        filesystem_group_id=1000,
                        uncertainty_reason=None,
                    ),
                    effective_capabilities=(
                        audit_under_test.EffectiveLinuxCapabilityMaskEvidence(
                            capability_mask=effective_capability_mask,
                            uncertainty_reason=None,
                        )
                    ),
                )
                faccessat_fallback = mock.Mock(return_value=0)
                with (
                    mock.patch.object(
                        audit_under_test,
                        "call_linux_faccessat2",
                        side_effect=unavailable_faccessat2,
                    ),
                    mock.patch.object(
                        audit_under_test,
                        "_LINUX_FACCESSAT_FUNCTION",
                        faccessat_fallback,
                    ),
                ):
                    evidence = audit_under_test.ask_kernel_about_path_access(
                        "/modeled",
                        os.W_OK,
                        process_credentials=process_credentials,
                    )

                faccessat_fallback.assert_not_called()
                self.assertIsNone(evidence.access_is_allowed)
                self.assertEqual(
                    evidence.uncertainty_reason.reason_code,
                    "linux_faccessat2_unavailable_and_faccessat_semantics_are_not_equivalent",
                )

    def test_clearable_immutable_flag_is_uncertain_not_permanently_blocked(
        self,
    ) -> None:
        credentials = current_credential_evidence()
        filesystem_user_id = credentials.filesystem_identifiers.filesystem_user_id
        self.assertIsNotNone(filesystem_user_id)
        capability_mask = (
            1 << audit_under_test.LINUX_CAPABILITY_LINUX_IMMUTABLE_NUMBER
        ) | (1 << audit_under_test.LINUX_CAPABILITY_FOWNER_NUMBER)
        privileged_credentials = replace(
            credentials,
            effective_capabilities=audit_under_test.EffectiveLinuxCapabilityMaskEvidence(
                capability_mask=capability_mask,
                uncertainty_reason=None,
            ),
        )
        active_auditor = permission_auditor(process_credentials=privileged_credentials)

        reasons, is_uncertain, is_blocked = (
            active_auditor._infer_set_inode_flag_constraint(
                attribute_is_set=True,
                inode_owner_user_id=filesystem_user_id,
                blocking_reason_code="blocked",
                potentially_clearable_reason_code="may_be_clearable",
            )
        )

        self.assertTrue(is_uncertain)
        self.assertFalse(is_blocked)
        self.assertEqual(reasons[0].reason_code, "may_be_clearable")

    def test_filesystem_identifiers_are_read_from_current_thread_status(
        self,
    ) -> None:
        process_status_stream = io.StringIO(
            "Name:\ttest\nUid:\t1000\t1001\t1002\t1003\nGid:\t2000\t2001\t2002\t2003\n"
        )
        with mock.patch(
            "builtins.open",
            return_value=process_status_stream,
        ):
            filesystem_identifiers = (
                audit_under_test.observe_linux_filesystem_identifiers(
                    expected_real_effective_saved_user_ids=(1000, 1001, 1002),
                    expected_real_effective_saved_group_ids=(2000, 2001, 2002),
                )
            )

        self.assertEqual(filesystem_identifiers.filesystem_user_id, 1003)
        self.assertEqual(filesystem_identifiers.filesystem_group_id, 2003)
        self.assertIsNone(filesystem_identifiers.uncertainty_reason)
        self.assertEqual(
            filesystem_identifiers.source_path,
            audit_under_test.LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
        )

    def test_distinct_filesystem_ids_make_effective_id_access_query_uncertain(
        self,
    ) -> None:
        process_credentials = mock.Mock(
            effective_user_id=1001,
            effective_group_id=2001,
            filesystem_identifiers=audit_under_test.LinuxFilesystemIdentifierEvidence(
                filesystem_user_id=1003,
                filesystem_group_id=2003,
                uncertainty_reason=None,
            ),
        )
        with mock.patch.object(audit_under_test.os, "access") as effective_access_query:
            access_evidence = audit_under_test.ask_kernel_about_path_access(
                "/observed-path",
                os.W_OK,
                process_credentials=process_credentials,
            )

        self.assertIsNone(access_evidence.access_is_allowed)
        self.assertEqual(
            access_evidence.uncertainty_reason.reason_code,
            "effective_id_access_query_cannot_model_distinct_filesystem_ids",
        )
        effective_access_query.assert_not_called()

    def test_unreadable_process_status_does_not_mean_zero_capabilities(
        self,
    ) -> None:
        with mock.patch(
            "builtins.open",
            side_effect=PermissionError(13, "Permission denied"),
        ):
            capability_evidence = (
                audit_under_test.observe_effective_linux_capability_mask()
            )

        self.assertIsNone(capability_evidence.capability_mask)
        self.assertIsNotNone(capability_evidence.uncertainty_reason)
        self.assertEqual(
            capability_evidence.uncertainty_reason.reason_code,
            "cannot_read_effective_linux_capabilities",
        )

    def test_unsupported_statx_attribute_bits_are_observed_as_clear(
        self,
    ) -> None:
        def statx_without_supported_attributes(
            directory_file_descriptor,
            encoded_path,
            lookup_flags,
            requested_mask,
            statx_record_pointer,
        ):
            del (
                directory_file_descriptor,
                encoded_path,
                lookup_flags,
                requested_mask,
            )
            statx_record = ctypes.cast(
                statx_record_pointer,
                ctypes.POINTER(audit_under_test.LinuxStatxStructure),
            ).contents
            statx_record.stx_attributes = 0
            statx_record.stx_attributes_mask = 0
            return 0

        with (
            mock.patch.object(
                audit_under_test,
                "_LINUX_STATX_FUNCTION",
                statx_without_supported_attributes,
            ),
            mock.patch.object(
                audit_under_test,
                "RUNNING_LINUX_KERNEL_RELEASE",
                "5.4.0",
            ),
        ):
            pre_statx_verity_evidence = audit_under_test.observe_linux_inode_attributes(
                "/", follow_final_symbolic_link=True
            )

        self.assertFalse(pre_statx_verity_evidence.immutable_attribute_is_set)
        self.assertFalse(pre_statx_verity_evidence.append_only_attribute_is_set)
        self.assertIsNone(pre_statx_verity_evidence.verity_attribute_is_set)
        self.assertEqual(
            pre_statx_verity_evidence.verity_uncertainty_reason.reason_code,
            "running_kernel_predates_documented_statx_verity_reporting",
        )
        self.assertEqual(pre_statx_verity_evidence.uncertainty_reasons, ())

        with (
            mock.patch.object(
                audit_under_test,
                "_LINUX_STATX_FUNCTION",
                statx_without_supported_attributes,
            ),
            mock.patch.object(
                audit_under_test,
                "RUNNING_LINUX_KERNEL_RELEASE",
                "5.5.0",
            ),
        ):
            documented_statx_verity_evidence = (
                audit_under_test.observe_linux_inode_attributes(
                    "/", follow_final_symbolic_link=True
                )
            )

        self.assertFalse(documented_statx_verity_evidence.verity_attribute_is_set)
        self.assertIsNone(documented_statx_verity_evidence.verity_uncertainty_reason)

    def test_verity_attribute_blocks_regular_file_content_mutation(self) -> None:
        active_auditor = permission_auditor()
        verity_evidence = audit_under_test.LinuxInodeAttributeEvidence(
            immutable_attribute_is_set=False,
            append_only_attribute_is_set=False,
            verity_attribute_is_set=True,
        )
        with (
            mock.patch.object(
                audit_under_test,
                "observe_linux_inode_attributes",
                return_value=verity_evidence,
            ),
            mock.patch.object(
                active_auditor,
                "ask_kernel_about_access",
                return_value=audit_under_test.KernelPathAccessEvidence(
                    access_is_allowed=True,
                    uncertainty_reason=None,
                ),
            ),
        ):
            overwrite_inference = active_auditor.infer_regular_file_content_mutation(
                "/modeled-file",
                audit_under_test.FILESYSTEM_OBJECT_KIND_REGULAR_FILE,
                audit_under_test.CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT,
            )

        self.assertEqual(
            overwrite_inference.model_verdict,
            audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED,
        )
        self.assertIn(
            "target_verity_attribute_blocks_content_mutation",
            {reason.reason_code for reason in overwrite_inference.evidence_reasons},
        )

    def test_unknown_cap_fowner_makes_sticky_rule_uncertain(self) -> None:
        observed_credentials = current_credential_evidence()
        uncertain_credentials = audit_under_test.LinuxProcessCredentialEvidence(
            access_identity_model=(
                audit_under_test.ACCESS_IDENTITY_MODEL_FILESYSTEM_AUTHORITY_WHEN_IDS_MATCH
            ),
            real_user_id=observed_credentials.real_user_id,
            effective_user_id=observed_credentials.effective_user_id,
            saved_user_id=observed_credentials.saved_user_id,
            real_group_id=observed_credentials.real_group_id,
            effective_group_id=observed_credentials.effective_group_id,
            saved_group_id=observed_credentials.saved_group_id,
            supplementary_group_ids=(observed_credentials.supplementary_group_ids),
            effective_capabilities=(
                audit_under_test.EffectiveLinuxCapabilityMaskEvidence(
                    capability_mask=None,
                    uncertainty_reason=audit_under_test.EvidenceReason(
                        "simulated_missing_capability_evidence",
                        evidence_source="test",
                    ),
                )
            ),
            filesystem_identifiers=audit_under_test.LinuxFilesystemIdentifierEvidence(
                filesystem_user_id=observed_credentials.effective_user_id,
                filesystem_group_id=observed_credentials.effective_group_id,
                uncertainty_reason=None,
            ),
        )
        active_auditor = permission_auditor(process_credentials=uncertain_credentials)
        unrelated_user_id = uncertain_credentials.effective_user_id + 100_000
        sticky_parent_metadata = mock.Mock(
            st_mode=stat.S_IFDIR | stat.S_ISVTX | 0o777,
            st_uid=unrelated_user_id,
        )
        unrelated_target_metadata = mock.Mock(st_uid=unrelated_user_id + 1)

        (
            evidence_reasons,
            model_is_uncertain,
            model_is_blocked,
        ) = active_auditor._infer_sticky_directory_deletion_constraint(
            sticky_parent_metadata,
            unrelated_target_metadata,
        )

        self.assertTrue(model_is_uncertain)
        self.assertFalse(model_is_blocked)
        self.assertEqual(
            evidence_reasons[0].reason_code,
            "simulated_missing_capability_evidence",
        )

    def test_deletion_observes_resolved_parent_not_symlink_inode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            resolved_parent = fixture_root / "resolved_parent"
            resolved_parent.mkdir()
            parent_symbolic_link = fixture_root / "parent_symbolic_link"
            parent_symbolic_link.symlink_to(resolved_parent)
            target_through_symbolic_parent = parent_symbolic_link / "target"
            (resolved_parent / "target").write_bytes(b"target")

            unrelated_user_id = os.geteuid() + 100_000
            sticky_resolved_parent_metadata = mock.Mock(
                st_mode=stat.S_IFDIR | stat.S_ISVTX | 0o777,
                st_uid=unrelated_user_id,
            )
            unrelated_target_metadata = mock.Mock(
                st_mode=stat.S_IFREG | 0o600,
                st_uid=unrelated_user_id + 1,
            )
            real_os_stat = os.stat

            def stat_with_distinct_resolved_parent(path, *arguments, **kwargs):
                if str(path) == str(parent_symbolic_link):
                    return sticky_resolved_parent_metadata
                return real_os_stat(path, *arguments, **kwargs)

            with (
                mock.patch.object(
                    audit_under_test.os,
                    "stat",
                    side_effect=stat_with_distinct_resolved_parent,
                ),
                inode_attributes_observed_clear(),
            ):
                delete_inference = permission_auditor().infer_delete_entry_or_tree(
                    str(target_through_symbolic_parent),
                    unrelated_target_metadata,
                    has_uncertain_descendant_delete=False,
                    has_blocked_descendant_delete=False,
                    directory_listing_failure=None,
                )

            self.assertEqual(
                delete_inference.model_verdict,
                audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED,
            )
            self.assertIn(
                "sticky_directory_ownership_rule_blocks_deletion",
                {reason.reason_code for reason in delete_inference.evidence_reasons},
            )


class DirectoryTraversalVerificationTests(unittest.TestCase):
    def test_every_dataclass_type_hint_resolves_on_supported_runtimes(self) -> None:
        dataclass_types = [
            value
            for value in vars(audit_under_test).values()
            if isinstance(value, type) and dataclasses.is_dataclass(value)
        ]
        for dataclass_type in dataclass_types:
            hints = typing.get_type_hints(dataclass_type)
            if "directory_iterator" in hints:
                self.assertNotIn(
                    "os.ScandirIterator",
                    repr(hints["directory_iterator"]),
                )

    def test_live_filename_ending_deleted_is_not_reported_as_unlinked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            live_path = Path(temporary_directory) / "literal (deleted)"
            live_path.write_bytes(b"live")
            descriptor = os.open(
                live_path,
                getattr(os, "O_PATH", 0o10000000),
            )
            try:
                observed_path, observation_note = (
                    audit_under_test.observe_canonical_path_for_file_descriptor(
                        descriptor,
                        fallback_path=str(live_path),
                    )
                )
            finally:
                os.close(descriptor)

        self.assertEqual(observed_path, str(live_path))
        self.assertIsNone(observation_note)

    def test_child_metadata_failures_become_path_and_parent_uncertainty(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_directory = Path(temporary_directory) / "audited"
            audited_directory.mkdir()
            child_path = audited_directory / "child"
            child_path.write_bytes(b"child")
            real_open = audit_under_test.os.open

            for simulated_error, expected_kind, expected_reason_code in (
                (
                    FileNotFoundError(errno.ENOENT, "simulated disappearance"),
                    audit_under_test.FILESYSTEM_OBJECT_KIND_MISSING,
                    "path_disappeared_during_directory_scan",
                ),
                (
                    PermissionError(errno.EACCES, "simulated capture denial"),
                    audit_under_test.FILESYSTEM_OBJECT_KIND_UNOBSERVED,
                    "cannot_capture_directory_entry",
                ),
            ):
                with self.subTest(reason_code=expected_reason_code):

                    def open_with_child_failure(
                        path,
                        flags,
                        mode=0o777,
                        *,
                        dir_fd=None,
                        simulated_child_error=simulated_error,
                    ):
                        if path == child_path.name and dir_fd is not None:
                            raise simulated_child_error
                        return real_open(path, flags, mode, dir_fd=dir_fd)

                    with (
                        mock.patch.object(
                            audit_under_test.os,
                            "open",
                            side_effect=open_with_child_failure,
                        ),
                        inode_attributes_observed_clear(),
                    ):
                        assessments = list(
                            permission_auditor().assess_path_tree(
                                str(audited_directory),
                                selected_capabilities=(
                                    audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                                ),
                            )
                        )

                    child_assessment, parent_assessment = assessments
                    self.assertEqual(
                        child_assessment.filesystem_object_kind,
                        expected_kind,
                    )
                    self.assertIsNone(
                        child_assessment.audited_path_lstat_metadata,
                    )
                    self.assertEqual(
                        child_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
                        )
                        .evidence_reasons[0]
                        .reason_code,
                        expected_reason_code,
                    )
                    self.assertEqual(
                        parent_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
                        ).model_verdict,
                        audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                    )

    def test_opened_directory_identity_change_makes_every_verdict_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_directory = Path(temporary_directory) / "audited"
            audited_directory.mkdir()
            active_auditor = permission_auditor()
            open_directory_normally = active_auditor._open_directory_for_listing

            def open_directory_with_distinct_observed_identity(
                directory_file_descriptor: int,
            ) -> audit_under_test.OpenDirectoryForListingEvidence:
                normal_open_evidence = open_directory_normally(
                    directory_file_descriptor
                )
                return audit_under_test.OpenDirectoryForListingEvidence(
                    directory_iterator=normal_open_evidence.directory_iterator,
                    opened_directory_identity=(
                        audit_under_test.FilesystemObjectIdentity(
                            device_number=(
                                normal_open_evidence.opened_directory_identity.device_number
                            ),
                            inode_number=(
                                normal_open_evidence.opened_directory_identity.inode_number
                                + 1
                            ),
                        )
                    ),
                    noatime_was_used=normal_open_evidence.noatime_was_used,
                    observation_notes=(normal_open_evidence.observation_notes),
                )

            with mock.patch.object(
                active_auditor,
                "_open_directory_for_listing",
                side_effect=open_directory_with_distinct_observed_identity,
            ):
                assessment = list(
                    active_auditor.assess_path_tree(
                        str(audited_directory),
                        selected_capabilities=(
                            audit_under_test.CAPABILITY_EVALUATION_ORDER
                        ),
                    )
                )[-1]

        self.assertEqual(
            {
                inference.model_verdict
                for inference in (assessment.inference_by_capability_name.values())
            },
            {audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE},
        )
        for inference in assessment.inference_by_capability_name.values():
            self.assertIn(
                "directory_identity_changed_between_capture_and_listing",
                {reason.reason_code for reason in inference.evidence_reasons},
            )

    def test_streaming_traversal_preserves_arbitrary_linux_filename_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_directory = Path(temporary_directory) / "audited"
            audited_directory.mkdir()
            child_names = (
                b"z-last",
                b"a-first",
                b"non_utf8_\xff",
            )
            for child_name in child_names:
                child_path = os.fsencode(audited_directory) + b"/" + child_name
                file_descriptor = os.open(
                    child_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                os.close(file_descriptor)

            with inode_attributes_observed_clear():
                assessments = list(
                    permission_auditor().assess_path_tree(
                        str(audited_directory),
                        selected_capabilities=(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                        ),
                    )
                )

        observed_child_name_bytes = [
            os.fsencode(os.path.basename(assessment.audited_path))
            for assessment in assessments[:-1]
        ]
        self.assertCountEqual(observed_child_name_bytes, child_names)

    def test_first_child_is_emitted_before_directory_iterator_is_exhausted(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_directory = Path(temporary_directory) / "audited"
            audited_directory.mkdir()
            for child_number in range(64):
                (audited_directory / f"child-{child_number:03d}").write_bytes(b"x")
            active_auditor = permission_auditor()
            open_directory_normally = active_auditor._open_directory_for_listing
            next_call_count = 0

            class CountingDirectoryIterator:
                def __init__(self, wrapped_iterator):
                    self.wrapped_iterator = wrapped_iterator

                def __next__(self):
                    nonlocal next_call_count
                    next_call_count += 1
                    return next(self.wrapped_iterator)

                def close(self):
                    return self.wrapped_iterator.close()

            def open_counted_directory(directory_file_descriptor):
                evidence = open_directory_normally(directory_file_descriptor)
                return replace(
                    evidence,
                    directory_iterator=CountingDirectoryIterator(
                        evidence.directory_iterator
                    ),
                )

            traversal = active_auditor.assess_path_tree(
                str(audited_directory),
                selected_capabilities=(
                    audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                ),
            )
            with (
                mock.patch.object(
                    active_auditor,
                    "_open_directory_for_listing",
                    side_effect=open_counted_directory,
                ),
                inode_attributes_observed_clear(),
            ):
                first_assessment = next(traversal)
                traversal.close()

        self.assertEqual(next_call_count, 1)
        self.assertTrue(
            os.path.basename(first_assessment.audited_path).startswith("child-")
        )

    def test_parent_path_swap_cannot_redirect_descriptor_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            audited_directory = fixture_root / "audited"
            moved_audited_directory = fixture_root / "captured-original"
            attacker_directory = fixture_root / "attacker"
            audited_directory.mkdir()
            attacker_directory.mkdir()
            original_child = audited_directory / "child"
            attacker_child = attacker_directory / "child"
            original_child.write_bytes(b"original")
            attacker_child.write_bytes(b"attacker")
            original_identity = (
                audit_under_test.FilesystemObjectIdentity.from_stat_result(
                    os.lstat(original_child)
                )
            )
            attacker_identity = (
                audit_under_test.FilesystemObjectIdentity.from_stat_result(
                    os.lstat(attacker_child)
                )
            )
            active_auditor = permission_auditor()
            assess_leaf_normally = active_auditor.assess_non_directory_path
            swap_was_performed = False

            def swap_parent_then_assess(*args, **kwargs):
                nonlocal swap_was_performed
                if not swap_was_performed:
                    os.rename(audited_directory, moved_audited_directory)
                    audited_directory.symlink_to(attacker_directory)
                    swap_was_performed = True
                return assess_leaf_normally(*args, **kwargs)

            with (
                mock.patch.object(
                    active_auditor,
                    "assess_non_directory_path",
                    side_effect=swap_parent_then_assess,
                ),
                inode_attributes_observed_clear(),
            ):
                child_assessment, root_assessment = list(
                    active_auditor.assess_path_tree(
                        str(audited_directory),
                        selected_capabilities=(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                        ),
                    )
                )

        observed_child_identity = audit_under_test.FilesystemObjectIdentity(
            device_number=(child_assessment.audited_path_lstat_metadata.device_number),
            inode_number=child_assessment.audited_path_lstat_metadata.inode_number,
        )
        self.assertEqual(observed_child_identity, original_identity)
        self.assertNotEqual(observed_child_identity, attacker_identity)
        self.assertEqual(
            root_assessment.inference_for_capability(
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
            ).model_verdict,
            audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
        )

    def test_material_child_delete_uncertainty_propagates_through_ancestors(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root_directory = Path(temporary_directory) / "root"
            child_directory = root_directory / "child"
            child_directory.mkdir(parents=True)
            leaf_path = child_directory / "leaf"
            leaf_path.write_bytes(b"leaf")
            active_auditor = permission_auditor()
            assess_leaf_normally = active_auditor.assess_non_directory_path

            def assess_leaf_with_material_failure(*args, **kwargs):
                assessment = assess_leaf_normally(*args, **kwargs)
                if assessment.audited_path != str(leaf_path):
                    return assessment
                return active_auditor._same_verdict_for_all_capabilities(
                    filesystem_object_kind=assessment.filesystem_object_kind,
                    audited_path=assessment.audited_path,
                    selected_capabilities=(
                        audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                    ),
                    model_verdict=(
                        audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE
                    ),
                    evidence_reasons=(
                        audit_under_test.EvidenceReason(
                            "cannot_observe_simulated_leaf_identity",
                            evidence_source="test",
                        ),
                    ),
                )

            with (
                mock.patch.object(
                    active_auditor,
                    "assess_non_directory_path",
                    side_effect=assess_leaf_with_material_failure,
                ),
                inode_attributes_observed_clear(),
            ):
                assessments = list(
                    active_auditor.assess_path_tree(
                        str(root_directory),
                        selected_capabilities=(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                        ),
                    )
                )

        assessment_by_path = {
            assessment.audited_path: assessment for assessment in assessments
        }
        for ancestor_path in (child_directory, root_directory):
            delete_inference = assessment_by_path[str(ancestor_path)].inference_for_capability(
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
            )
            self.assertEqual(
                delete_inference.model_verdict,
                audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
            )
            material_aggregation_reason = next(
                reason
                for reason in delete_inference.evidence_reasons
                if reason.reason_code
                == "at_least_one_descendant_has_material_uncertain_delete_inference"
            )
            self.assertEqual(
                audit_under_test.evidence_reason_uncertainty_grade(
                    material_aggregation_reason
                ),
                audit_under_test.UNCERTAINTY_GRADE_MATERIAL,
            )
            self.assertIn("descendant_path_bytes_base64=", material_aggregation_reason.detail)

    def test_file_descriptor_exhaustion_stops_scope_with_named_uncertainty(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_directory = Path(temporary_directory) / "audited"
            audited_directory.mkdir()
            (audited_directory / "child").write_bytes(b"child")
            real_open = audit_under_test.os.open

            def open_with_exhausted_child_budget(
                path,
                flags,
                mode=0o777,
                *,
                dir_fd=None,
            ):
                if path == "child" and dir_fd is not None:
                    raise OSError(errno.EMFILE, "simulated descriptor exhaustion")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(
                    audit_under_test.os,
                    "open",
                    side_effect=open_with_exhausted_child_budget,
                ),
                inode_attributes_observed_clear(),
            ):
                assessments = list(
                    permission_auditor().assess_path_tree(
                        str(audited_directory),
                        selected_capabilities=(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                        ),
                    )
                )

        self.assertEqual(len(assessments), 1)
        delete_inference = assessments[0].inference_for_capability(
            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
        )
        self.assertEqual(
            delete_inference.model_verdict,
            audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
        )
        self.assertIn(
            "directory_traversal_file_descriptor_budget_exhausted",
            {reason.reason_code for reason in delete_inference.evidence_reasons},
        )

    def test_listing_failure_marks_scope_incomplete_without_delete_capability(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_directory = Path(temporary_directory) / "audited"
            audited_directory.mkdir()
            (audited_directory / "child").write_bytes(b"child")
            real_open = audit_under_test.os.open

            def open_with_exhausted_child_budget(
                path,
                flags,
                mode=0o777,
                *,
                dir_fd=None,
            ):
                if path == "child" and dir_fd is not None:
                    raise OSError(errno.EMFILE, "simulated descriptor exhaustion")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(
                    audit_under_test.os,
                    "open",
                    side_effect=open_with_exhausted_child_budget,
                ),
                inode_attributes_observed_clear(),
            ):
                assessments = list(
                    permission_auditor().assess_path_tree(
                        str(audited_directory),
                        selected_capabilities=(
                            audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                        ),
                    )
                )

        self.assertEqual(len(assessments), 1)
        self.assertTrue(
            audit_under_test.assessment_has_enumeration_uncertainty(assessments[0])
        )
        self.assertIn(
            "directory_traversal_file_descriptor_budget_exhausted",
            {reason.reason_code for reason in assessments[0].observation_notes},
        )

    @unittest.skipUnless(
        getattr(os, "O_NOATIME", 0),
        "runtime does not expose Linux O_NOATIME",
    )
    def test_owned_directory_scan_preserves_observed_access_time(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_directory = Path(temporary_directory) / "audited"
            audited_directory.mkdir()
            (audited_directory / "child").write_bytes(b"child")
            historical_atime_nanoseconds = 946_684_800_000_000_000
            current_mtime_nanoseconds = audited_directory.stat().st_mtime_ns
            os.utime(
                audited_directory,
                ns=(
                    historical_atime_nanoseconds,
                    current_mtime_nanoseconds,
                ),
            )

            with inode_attributes_observed_clear():
                directory_assessment = list(
                    permission_auditor().assess_path_tree(
                        str(audited_directory),
                        selected_capabilities=(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                        ),
                    )
                )[-1]

            observed_atime_nanoseconds = audited_directory.stat().st_atime_ns

        self.assertEqual(
            observed_atime_nanoseconds,
            historical_atime_nanoseconds,
        )
        self.assertNotIn(
            "directory_read_retried_without_o_noatime",
            {reason.reason_code for reason in directory_assessment.observation_notes},
        )

    def test_traversal_depth_exceeding_python_recursion_limit_is_iterative(
        self,
    ) -> None:
        traversal_root = Path(tempfile.mkdtemp(prefix="audit-depth-"))
        created_directories: list[Path] = []
        try:
            current_directory = traversal_root
            requested_depth = sys.getrecursionlimit() + 50
            for _depth_index in range(requested_depth):
                current_directory = current_directory / "d"
                current_directory.mkdir()
                created_directories.append(current_directory)

            assessments = list(
                permission_auditor().assess_path_tree(
                    str(traversal_root),
                    selected_capabilities=(
                        audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                    ),
                )
            )

            self.assertEqual(
                len(assessments),
                requested_depth + 1,
            )
            self.assertEqual(
                assessments[0].audited_path,
                str(created_directories[-1]),
            )
            self.assertEqual(
                assessments[-1].audited_path,
                str(traversal_root),
            )
        finally:
            for created_directory in reversed(created_directories):
                created_directory.rmdir()
            traversal_root.rmdir()


class LinuxMountEvidenceVerificationTests(unittest.TestCase):
    def test_mountinfo_octal_escape_and_summary_preserve_high_filename_byte(
        self,
    ) -> None:
        decoded_mount_point = audit_under_test.unescape_linux_mountinfo_field(
            r"/mount/bad-\377"
        )
        self.assertEqual(os.fsencode(decoded_mount_point), b"/mount/bad-\xff")
        mount_record = audit_under_test.LinuxMountRecord(
            mount_id=10,
            parent_mount_id=1,
            mount_point=decoded_mount_point,
            filesystem_type="testfs",
            mount_options=("rw",),
            superblock_options=("rw",),
            mountinfo_line_number=1,
        )
        summary = audit_under_test.linux_mount_record_evidence_summary(mount_record)
        encoded_mount_point = summary.split(
            "mount_point_bytes_base64=", 1
        )[1].split(";", 1)[0]
        self.assertEqual(
            base64.b64decode(encoded_mount_point),
            b"/mount/bad-\xff",
        )

    def test_symlink_loop_resolution_becomes_named_mount_uncertainty(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            first_link = fixture_root / "first-link"
            second_link = fixture_root / "second-link"
            first_link.symlink_to(second_link.name)
            second_link.symlink_to(first_link.name)

            unresolved_path, uncertainty_reason = (
                audit_under_test.best_effort_resolve_existing_path(str(first_link))
            )

        self.assertEqual(unresolved_path, str(first_link))
        self.assertEqual(
            uncertainty_reason.reason_code,
            "cannot_resolve_path_for_mount_lookup",
        )
        self.assertEqual(
            uncertainty_reason.evidence_source,
            audit_under_test.STRICT_PATH_RESOLUTION_EVIDENCE_SOURCE,
        )

    def test_malformed_mountinfo_degrades_to_named_uncertainty(self) -> None:
        malformed_mountinfo_bytes = b"not a mountinfo record\n"
        malformed_mountinfo = io.BytesIO(malformed_mountinfo_bytes)
        with mock.patch(
            "builtins.open",
            return_value=malformed_mountinfo,
        ):
            mount_table_evidence = (
                audit_under_test.read_current_process_linux_mount_table()
            )

        self.assertTrue(mount_table_evidence.evidence_is_degraded)
        self.assertEqual(
            mount_table_evidence.uncertainty_reasons[0].reason_code,
            "cannot_parse_linux_mount_table",
        )
        self.assertEqual(
            mount_table_evidence.mount_records[0].filesystem_type,
            "unknown",
        )
        self.assertEqual(
            mount_table_evidence.source_sha256,
            hashlib.sha256(malformed_mountinfo_bytes).hexdigest(),
        )

    def test_duplicate_mount_ids_and_parent_cycles_are_refused(self) -> None:
        duplicate_mount_id_records = (
            audit_under_test.LinuxMountRecord(
                mount_id=1,
                parent_mount_id=0,
                mount_point="/",
                filesystem_type="ext4",
                mount_options=("rw",),
                superblock_options=("rw",),
                mountinfo_line_number=1,
            ),
            audit_under_test.LinuxMountRecord(
                mount_id=1,
                parent_mount_id=0,
                mount_point="/other",
                filesystem_type="tmpfs",
                mount_options=("rw",),
                superblock_options=("rw",),
                mountinfo_line_number=2,
            ),
        )
        with self.assertRaisesRegex(ValueError, "duplicate mount ID 1"):
            audit_under_test.validate_linux_mount_record_graph(
                duplicate_mount_id_records
            )

        parent_cycle_records = (
            audit_under_test.LinuxMountRecord(
                mount_id=1,
                parent_mount_id=2,
                mount_point="/",
                filesystem_type="ext4",
                mount_options=("rw",),
                superblock_options=("rw",),
                mountinfo_line_number=1,
            ),
            audit_under_test.LinuxMountRecord(
                mount_id=2,
                parent_mount_id=1,
                mount_point="/child",
                filesystem_type="tmpfs",
                mount_options=("rw",),
                superblock_options=("rw",),
                mountinfo_line_number=2,
            ),
        )
        with self.assertRaisesRegex(ValueError, "mount parent cycle"):
            audit_under_test.validate_linux_mount_record_graph(parent_cycle_records)

    def test_non_utf8_mountpoint_bytes_survive_mountinfo_parsing(
        self,
    ) -> None:
        root_record = b"1 0 8:1 / / rw - ext4 /dev/root rw\n"
        non_utf8_mount_record = b"2 1 8:2 / /tmp/non_utf8_\xff rw - ext4 /dev/data rw\n"
        mountinfo_stream = io.BytesIO(root_record + non_utf8_mount_record)
        with mock.patch(
            "builtins.open",
            return_value=mountinfo_stream,
        ):
            mount_table_evidence = (
                audit_under_test.read_current_process_linux_mount_table()
            )

        self.assertFalse(mount_table_evidence.evidence_is_degraded)
        self.assertEqual(
            os.fsencode(mount_table_evidence.mount_records[1].mount_point),
            b"/tmp/non_utf8_\xff",
        )

    def test_utf8_non_ascii_whitespace_is_mountpoint_data_not_a_delimiter(
        self,
    ) -> None:
        root_record = b"1 0 8:1 / / rw - ext4 /dev/root rw\n"
        mountpoint_with_unicode_next_line_character = (
            b"/tmp/unicode_\xc2\x85_mountpoint"
        )
        unicode_mount_record = (
            b"2 1 8:2 / "
            + mountpoint_with_unicode_next_line_character
            + b" rw - ext4 /dev/data rw\n"
        )
        mountinfo_stream = io.BytesIO(root_record + unicode_mount_record)
        with mock.patch(
            "builtins.open",
            return_value=mountinfo_stream,
        ):
            mount_table_evidence = (
                audit_under_test.read_current_process_linux_mount_table()
            )

        self.assertFalse(mount_table_evidence.evidence_is_degraded)
        self.assertEqual(len(mount_table_evidence.mount_records), 2)
        self.assertEqual(
            os.fsencode(mount_table_evidence.mount_records[1].mount_point),
            mountpoint_with_unicode_next_line_character,
        )

    def test_same_mountpoint_depth_is_not_python_recursive(self) -> None:
        depth_beyond_python_recursion = sys.getrecursionlimit() + 100
        mount_records = [
            audit_under_test.LinuxMountRecord(
                mount_id=mount_id,
                parent_mount_id=mount_id - 1 if mount_id > 1 else 0,
                mount_point="/",
                filesystem_type="tmpfs",
                mount_options=("rw",),
                superblock_options=("rw",),
                mountinfo_line_number=mount_id,
            )
            for mount_id in range(
                1,
                depth_beyond_python_recursion + 1,
            )
        ]

        records_with_depth = audit_under_test.add_same_mountpoint_stack_depths(
            mount_records
        )

        self.assertEqual(
            records_with_depth[-1].same_mountpoint_stack_depth,
            depth_beyond_python_recursion - 1,
        )

    def test_deleting_symlink_to_mountpoint_does_not_follow_final_link(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            modeled_mountpoint = fixture_root / "modeled_mountpoint"
            modeled_mountpoint.mkdir()
            mountpoint_symbolic_link = fixture_root / "mountpoint_symbolic_link"
            mountpoint_symbolic_link.symlink_to(modeled_mountpoint)

            mount_records = (
                audit_under_test.LinuxMountRecord(
                    mount_id=1,
                    parent_mount_id=0,
                    mount_point="/",
                    filesystem_type="ext4",
                    mount_options=("rw",),
                    superblock_options=("rw",),
                    mountinfo_line_number=1,
                ),
                audit_under_test.LinuxMountRecord(
                    mount_id=2,
                    parent_mount_id=1,
                    mount_point=str(modeled_mountpoint),
                    filesystem_type="tmpfs",
                    mount_options=("rw",),
                    superblock_options=("rw",),
                    mountinfo_line_number=2,
                ),
            )
            mount_table = audit_under_test.VisibleLinuxMountTable(
                audit_under_test.LinuxMountTableReadEvidence(
                    mount_records=mount_records,
                    uncertainty_reasons=(),
                    source_path="test mountinfo",
                    source_sha256=None,
                    observed_at_utc=audit_under_test.current_utc_timestamp(),
                )
            )

            (
                symbolic_link_is_mountpoint,
                uncertainty_reasons,
            ) = mount_table.observe_path_is_visible_mountpoint(
                str(mountpoint_symbolic_link)
            )

            self.assertFalse(symbolic_link_is_mountpoint)
            self.assertEqual(uncertainty_reasons, ())


class CommandAndReportTransportContractTests(unittest.TestCase):
    def test_help_names_each_canonical_operation_capability(self) -> None:
        completed_command = run_audit_tool_command("--help")

        self.assertEqual(completed_command.returncode, 0)
        decoded_help = completed_command.stdout.decode("utf-8")
        for capability_name in audit_under_test.CAPABILITY_EVALUATION_ORDER:
            with self.subTest(capability_name=capability_name):
                self.assertIn(capability_name, decoded_help)
                self.assertIn(
                    audit_under_test.CAPABILITY_OPERATION_DEFINITION_BY_NAME[
                        capability_name
                    ],
                    decoded_help,
                )
        for presentation_override in (
            "--tty",
            "--human",
            "--json",
            "--machine",
        ):
            self.assertIn(presentation_override, decoded_help)
        self.assertIn(
            "terminal stdout             compact human-readable path lines",
            decoded_help,
        )
        self.assertIn(
            "redirected or piped stdout  self-contained JSON Lines records",
            decoded_help,
        )

    def test_non_linux_platform_gets_explicit_backend_diagnostic(self) -> None:
        diagnostic_stream = io.StringIO()
        with (
            mock.patch.object(audit_under_test.sys, "platform", "darwin"),
            contextlib.redirect_stderr(diagnostic_stream),
        ):
            exit_status = audit_under_test.run_audit_command(("/scope",))

        self.assertEqual(exit_status, audit_under_test.EXIT_COMMAND_LINE_REFUSED)
        self.assertIn("only the Linux evidence backend", diagnostic_stream.getvalue())
        self.assertIn("Darwin and BSD", diagnostic_stream.getvalue())

    def test_non_linux_platform_is_guarded_during_module_initialization(self) -> None:
        child_environment = os.environ.copy()
        child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        command_source = (
            "import runpy, sys; "
            "sys.platform = 'darwin'; "
            f"sys.argv = [{str(AUDIT_SCRIPT_PATH)!r}, '/scope']; "
            f"runpy.run_path({str(AUDIT_SCRIPT_PATH)!r}, run_name='__main__')"
        )
        completed_command = subprocess.run(
            [sys.executable, "-c", command_source],
            capture_output=True,
            env=child_environment,
            timeout=30,
            check=False,
        )

        self.assertEqual(
            completed_command.returncode,
            audit_under_test.EXIT_COMMAND_LINE_REFUSED,
        )
        self.assertIn(
            b"only the Linux evidence backend",
            completed_command.stderr,
        )

    def test_fail_on_uncertainty_writes_completion_then_exits_five(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_file = Path(temporary_directory) / "audited"
            audited_file.write_bytes(b"content")
            missing_exclusion = Path(temporary_directory) / "missing-exclusion"
            completed_command = run_audit_tool_command(
                "--fail-on-uncertainty",
                "--exclude",
                missing_exclusion,
                audited_file,
            )

        decoded_records = [
            json.loads(line)
            for line in completed_command.stdout.decode("ascii").splitlines()
        ]
        self.assertEqual(
            completed_command.returncode,
            audit_under_test.EXIT_AUDIT_EVIDENCE_UNCERTAIN,
        )
        completion_record = decoded_records[-1]
        self.assertEqual(completion_record["record_type"], "audit_run_completion")
        self.assertTrue(completion_record["audit_algorithm_completed"])
        self.assertTrue(
            completion_record["uncertainty_policy"]["uncertainty_was_observed"]
        )
        self.assertFalse(
            completion_record["uncertainty_policy"]["policy_was_satisfied"]
        )

    def test_material_uncertainty_is_quiet_but_retained_in_default_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_file = Path(temporary_directory) / "audited"
            audited_file.write_bytes(b"content")
            missing_exclusion = Path(temporary_directory) / "missing-exclusion"
            completed_command = run_audit_tool_command(
                "--exclude",
                missing_exclusion,
                audited_file,
            )

        self.assertEqual(completed_command.returncode, 0)
        self.assertEqual(completed_command.stderr, b"")
        decoded_records = [
            json.loads(line)
            for line in completed_command.stdout.decode("ascii").splitlines()
        ]
        completion_record = decoded_records[-1]
        self.assertTrue(
            completion_record["uncertainty_policy"]["uncertainty_was_observed"]
        )
        self.assertEqual(
            completion_record["statistics"]["material_uncertainty"][
                "run_level_uncertainty_reason_count"
            ],
            1,
        )

    def test_routine_uncertainty_is_hidden_unless_full_audit_is_requested(
        self,
    ) -> None:
        routine_reason = audit_under_test.EvidenceReason(
            "cannot_list_directory",
            evidence_source="os.scandir",
            operating_system_errno=errno.EACCES,
        )
        material_reason = audit_under_test.EvidenceReason(
            "cannot_list_directory",
            evidence_source="os.scandir",
            operating_system_errno=errno.EIO,
        )
        self.assertEqual(
            audit_under_test.evidence_reason_uncertainty_grade(routine_reason),
            audit_under_test.UNCERTAINTY_GRADE_ROUTINE,
        )
        self.assertEqual(
            audit_under_test.evidence_reason_uncertainty_grade(material_reason),
            audit_under_test.UNCERTAINTY_GRADE_MATERIAL,
        )

        statistics = audit_under_test.AuditRunStatistics(
            uncertain_path_count=1,
            selected_capability_uncertainty_path_count=1,
            enumeration_uncertainty_path_count=1,
            routine_uncertain_path_count=1,
            routine_selected_capability_uncertainty_path_count=1,
            routine_enumeration_uncertainty_path_count=1,
        )
        default_statistics = statistics.as_serializable_dictionary(
            include_routine_uncertainty=False
        )
        full_statistics = statistics.as_serializable_dictionary(
            include_routine_uncertainty=True
        )
        self.assertNotIn("material_uncertainty", default_statistics)
        self.assertNotIn("uncertainty_by_grade", default_statistics)
        self.assertEqual(
            full_statistics["uncertainty_by_grade"]["routine"][
                "enumeration_uncertainty_path_count"
            ],
            1,
        )

        configuration = audit_under_test.parse_audit_command_line_arguments(
            ("--full-audit", "/scope")
        )
        self.assertTrue(configuration.full_audit)
        self.assertTrue(configuration.include_nonmatching_records)

        output_stream = io.StringIO()
        diagnostic_stream = io.StringIO()
        with (
            mock.patch.object(
                audit_under_test,
                "execute_audit_to_stream",
                return_value=audit_under_test.AuditExecutionResult(statistics),
            ),
            contextlib.redirect_stdout(output_stream),
            contextlib.redirect_stderr(diagnostic_stream),
        ):
            exit_status = audit_under_test.run_audit_command(
                ("--allow-root-audit", "--fail-on-uncertainty", "/scope")
            )
        self.assertEqual(exit_status, 0)
        self.assertEqual(diagnostic_stream.getvalue(), "")

    def test_default_json_keeps_permission_finding_but_omits_routine_branches(
        self,
    ) -> None:
        routine_reason = audit_under_test.EvidenceReason(
            "target_write_access_may_be_changeable_by_chmod",
            evidence_source="inode st_uid and filesystem UID",
        )
        assessment = audit_under_test.PathCapabilityAssessment(
            filesystem_object_kind=(
                audit_under_test.FILESYSTEM_OBJECT_KIND_REGULAR_FILE
            ),
            audited_path="/owner-read-only",
            inference_by_capability_name={
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE: (
                    audit_under_test.capability_inference(
                        audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                        audit_under_test.MODEL_VERDICT_INDICATES_ALLOWED,
                    )
                ),
                audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT: (
                    audit_under_test.capability_inference(
                        audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                        audit_under_test.MODEL_VERDICT_INSUFFICIENT_EVIDENCE,
                        (routine_reason,),
                    )
                ),
            },
        )
        record = assessment.create_structured_record(
            selected_capabilities=(
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
            ),
            originating_scan_root_path="/owner-read-only",
        )
        default_path_record = record.as_serializable_dictionary(
            serialized_audit_run_provenance={},
            include_routine_uncertainty=False,
        )
        self.assertIn(
            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
            default_path_record["model_indicated_capabilities"],
        )
        self.assertNotIn(
            "capabilities_with_insufficient_evidence",
            default_path_record,
        )
        self.assertNotIn("uncertainty_grade_by_capability", default_path_record)
        full_path_record = record.as_serializable_dictionary(
            serialized_audit_run_provenance={},
            include_routine_uncertainty=True,
        )
        self.assertEqual(
            full_path_record["uncertainty_grade_by_capability"][
                audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT
            ],
            audit_under_test.UNCERTAINTY_GRADE_ROUTINE,
        )

    def test_runtime_failure_leaves_jsonl_without_completion_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_file = Path(temporary_directory) / "audited"
            audited_file.write_bytes(b"content")
            output_stream = io.StringIO()
            diagnostic_stream = io.StringIO()
            with (
                mock.patch.object(
                    audit_under_test.LinuxFilesystemMutationPermissionAuditor,
                    "assess_path_tree",
                    side_effect=OSError(errno.EIO, "simulated traversal failure"),
                ),
                contextlib.redirect_stdout(output_stream),
                contextlib.redirect_stderr(diagnostic_stream),
            ):
                exit_status = audit_under_test.run_audit_command(
                    ("--allow-root-audit", str(audited_file))
                )

        record_types = [
            json.loads(line)["record_type"]
            for line in output_stream.getvalue().splitlines()
        ]
        self.assertEqual(exit_status, audit_under_test.EXIT_AUDIT_RUNTIME_FAILED)
        self.assertEqual(record_types, ["audit_run_provenance"])

    def test_output_presentation_uses_context_unless_explicitly_overridden(
        self,
    ) -> None:
        automatic_standard_output_configuration = (
            audit_under_test.parse_audit_command_line_arguments(("/explicit",))
        )
        terminal_stream = mock.Mock()
        terminal_stream.isatty.return_value = True
        redirected_stream = mock.Mock()
        redirected_stream.isatty.return_value = False

        self.assertEqual(
            audit_under_test.resolve_audit_output_presentation(
                automatic_standard_output_configuration,
                terminal_stream,
            ),
            audit_under_test.OUTPUT_PRESENTATION_TERMINAL_PATHS,
        )
        self.assertEqual(
            audit_under_test.resolve_audit_output_presentation(
                automatic_standard_output_configuration,
                redirected_stream,
            ),
            audit_under_test.OUTPUT_PRESENTATION_JSON_LINES,
        )

        automatic_file_configuration = (
            audit_under_test.parse_audit_command_line_arguments(
                ("--output", "/tmp/presentation-test", "/explicit")
            )
        )
        terminal_stream.isatty.reset_mock()
        self.assertEqual(
            audit_under_test.resolve_audit_output_presentation(
                automatic_file_configuration,
                terminal_stream,
            ),
            audit_under_test.OUTPUT_PRESENTATION_JSON_LINES,
        )
        terminal_stream.isatty.assert_not_called()

        for human_override in ("--tty", "--human"):
            with self.subTest(human_override=human_override):
                human_configuration = (
                    audit_under_test.parse_audit_command_line_arguments(
                        (human_override, "/explicit")
                    )
                )
                self.assertEqual(
                    audit_under_test.resolve_audit_output_presentation(
                        human_configuration,
                        redirected_stream,
                    ),
                    audit_under_test.OUTPUT_PRESENTATION_TERMINAL_PATHS,
                )

        for machine_override in ("--json", "--machine"):
            with self.subTest(machine_override=machine_override):
                machine_configuration = (
                    audit_under_test.parse_audit_command_line_arguments(
                        (machine_override, "/explicit")
                    )
                )
                self.assertEqual(
                    audit_under_test.resolve_audit_output_presentation(
                        machine_configuration,
                        terminal_stream,
                    ),
                    audit_under_test.OUTPUT_PRESENTATION_JSON_LINES,
                )

    def test_human_and_machine_overrides_are_mutually_exclusive(self) -> None:
        for contradictory_arguments in (
            ("--tty", "--json", "/explicit"),
            ("--human", "--machine", "/explicit"),
        ):
            with (
                self.subTest(arguments=contradictory_arguments),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised_exit,
            ):
                audit_under_test.parse_audit_command_line_arguments(
                    contradictory_arguments
                )
            self.assertEqual(
                raised_exit.exception.code,
                audit_under_test.EXIT_COMMAND_LINE_REFUSED,
            )

    def test_terminal_path_record_uses_compact_labels_and_path_conventions(
        self,
    ) -> None:
        directory_target_symbolic_link_record = mock.Mock(
            audited_path="/scope/link\nname",
            filesystem_object_kind=audit_under_test.FILESYSTEM_OBJECT_KIND_SYMBOLIC_LINK,
            resolved_symbolic_link_target_path="/target/directory",
            resolved_symbolic_link_target_kind=(
                audit_under_test.FILESYSTEM_OBJECT_KIND_DIRECTORY
            ),
            model_indicated_capabilities=(
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                audit_under_test.CAPABILITY_OVERWRITE_REGULAR_FILE_CONTENT,
                audit_under_test.CAPABILITY_CREATE_DIRECTORY_ENTRY,
                audit_under_test.CAPABILITY_SPECIAL_FILE_WRITE_PERMISSION,
            ),
        )
        terminal_output = io.StringIO()

        audit_under_test.write_terminal_path_audit_record(
            directory_target_symbolic_link_record,
            output_stream=terminal_output,
        )

        self.assertEqual(
            terminal_output.getvalue(),
            '[daocs] "/scope/link\\nname" -> "/target/directory/"\n',
        )

    def test_terminal_paths_escape_unicode_formatting_and_quote_link_sides(
        self,
    ) -> None:
        dangerous_text = (
            "name\u0085\u202e\u2028\u200b\u034f\u0301\ufe0f"
            "\U000e0100\u115f\u1160\u05d0"
        )
        self.assertEqual(
            audit_under_test.escape_linux_path_text_for_terminal(dangerous_text),
            (
                r"name\u0085\u202e\u2028\u200b\u034f\u0301\ufe0f"
                r"\U000e0100\u115f\u1160\u05d0"
            ),
        )
        ambiguous_symbolic_link_record = mock.Mock(
            audited_path="/scope/a -> b",
            filesystem_object_kind=(
                audit_under_test.FILESYSTEM_OBJECT_KIND_SYMBOLIC_LINK
            ),
            resolved_symbolic_link_target_path="target -> destination",
            resolved_symbolic_link_target_kind=(
                audit_under_test.FILESYSTEM_OBJECT_KIND_REGULAR_FILE
            ),
        )
        self.assertEqual(
            audit_under_test.terminal_path_description(
                ambiguous_symbolic_link_record
            ),
            '"/scope/a -> b" -> "target -> destination"',
        )

    def test_human_override_writes_paths_to_a_private_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_path = Path(temporary_directory) / "assessed-file"
            fixture_path.write_bytes(b"fixture")
            human_report_path = Path(temporary_directory) / "human-report.txt"

            completed_command = run_audit_tool_command(
                "--human",
                "--include-nonmatching-records",
                "--capability",
                audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT,
                "--output",
                str(human_report_path),
                str(fixture_path),
            )

            human_report_text = human_report_path.read_text(encoding="utf-8")

        self.assertEqual(completed_command.returncode, 0)
        self.assertEqual(completed_command.stdout, b"")
        self.assertEqual(completed_command.stderr, b"")
        self.assertIn(str(fixture_path), human_report_text)
        self.assertNotIn('"record_type"', human_report_text)

    def test_invalid_path_and_filesystem_type_inputs_are_refused(self) -> None:
        invalid_argument_lists = (
            ("\0",),
            ("--output", "\0", "/scope"),
            ("--uncertain-filesystem-type", "contains whitespace", "/scope"),
        )
        for invalid_arguments in invalid_argument_lists:
            with (
                self.subTest(arguments=invalid_arguments),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised_exit,
            ):
                audit_under_test.parse_audit_command_line_arguments(invalid_arguments)
            self.assertEqual(
                raised_exit.exception.code,
                audit_under_test.EXIT_COMMAND_LINE_REFUSED,
            )

    def test_effective_root_requires_current_explicit_authorization(self) -> None:
        diagnostic_stream = io.StringIO()
        with (
            mock.patch.object(audit_under_test.os, "geteuid", return_value=0),
            contextlib.redirect_stderr(diagnostic_stream),
        ):
            exit_status = audit_under_test.run_audit_command(("/scope",))

        self.assertEqual(exit_status, audit_under_test.EXIT_COMMAND_LINE_REFUSED)
        self.assertIn("effective-UID-0", diagnostic_stream.getvalue())

    def test_unavailable_stderr_does_not_turn_refusal_into_success(self) -> None:
        unavailable_standard_error = mock.Mock(encoding="utf-8")
        unavailable_standard_error.write.side_effect = BrokenPipeError(
            errno.EPIPE,
            "simulated closed stderr",
        )
        with (
            mock.patch.object(audit_under_test.os, "geteuid", return_value=0),
            mock.patch.object(
                audit_under_test.sys,
                "stderr",
                unavailable_standard_error,
            ),
        ):
            exit_status = audit_under_test.run_audit_command(("/scope",))

        self.assertEqual(exit_status, audit_under_test.EXIT_COMMAND_LINE_REFUSED)

    def test_unexpected_operating_system_error_is_an_audit_runtime_failure(
        self,
    ) -> None:
        diagnostic_stream = io.StringIO()
        with (
            mock.patch.object(
                audit_under_test,
                "execute_audit_to_stream",
                side_effect=OSError(errno.EIO, "simulated audit read failure"),
            ),
            contextlib.redirect_stderr(diagnostic_stream),
        ):
            exit_status = audit_under_test.run_audit_command(
                ("--allow-root-audit", "/scope")
            )

        self.assertEqual(exit_status, audit_under_test.EXIT_AUDIT_RUNTIME_FAILED)
        self.assertIn("audit runtime failed", diagnostic_stream.getvalue())

    def test_memory_exhaustion_is_a_named_audit_runtime_failure(self) -> None:
        diagnostic_stream = io.StringIO()
        with (
            mock.patch.object(
                audit_under_test,
                "execute_audit_to_stream",
                side_effect=MemoryError,
            ),
            contextlib.redirect_stderr(diagnostic_stream),
        ):
            exit_status = audit_under_test.run_audit_command(
                ("--allow-root-audit", "/scope")
            )

        self.assertEqual(exit_status, audit_under_test.EXIT_AUDIT_RUNTIME_FAILED)
        self.assertIn("process memory was exhausted", diagnostic_stream.getvalue())

    def test_incomplete_stream_write_is_a_named_transport_failure(self) -> None:
        short_writing_stream = mock.Mock()
        short_writing_stream.write.return_value = 1

        with self.assertRaisesRegex(
            audit_under_test.AuditReportTransportError,
            "incomplete JSONL record write",
        ):
            audit_under_test.write_json_line_to_audit_report(
                {"record_type": "transport_test"},
                output_stream=short_writing_stream,
            )

    def test_broken_stdout_pipe_before_completion_has_incomplete_exit_status(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_directory = Path(temporary_directory) / "audited"
            audited_directory.mkdir()
            for child_number in range(512):
                (audited_directory / f"child-{child_number:04d}").write_bytes(b"x")
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(AUDIT_SCRIPT_PATH),
                    "--allow-root-audit",
                    "--full-audit",
                    str(audited_directory),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            assert process.stdout is not None
            assert process.stderr is not None
            first_record = process.stdout.readline()
            process.stdout.close()
            standard_error = process.stderr.read()
            process.stderr.close()
            return_code = process.wait(timeout=30)

        self.assertTrue(first_record)
        self.assertEqual(
            return_code,
            audit_under_test.EXIT_AUDIT_REPORT_INCOMPLETE,
        )
        self.assertIn(b"before the complete audit", standard_error)


class JsonlEvidenceContractTests(unittest.TestCase):
    def test_loaded_code_identity_survives_source_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied_module_path = Path(temporary_directory) / "copied_auditor.py"
            copied_module_path.write_bytes(AUDIT_SCRIPT_PATH.read_bytes())
            module_name = f"copied_auditor_{uuid.uuid4().hex}"
            module_specification = importlib.util.spec_from_file_location(
                module_name,
                copied_module_path,
            )
            assert module_specification is not None
            assert module_specification.loader is not None
            copied_module = importlib.util.module_from_spec(module_specification)
            sys.modules[module_name] = copied_module
            try:
                module_specification.loader.exec_module(copied_module)
                loaded_code_digest = copied_module.LOADED_MODULE_CODE_SHA256
                replacement_source = b"# replacement after module execution\n"
                copied_module_path.write_bytes(replacement_source)
                observed_source = copied_module.observe_tool_source_file()
            finally:
                sys.modules.pop(module_name, None)

        self.assertEqual(
            observed_source.source_file_sha256,
            hashlib.sha256(replacement_source).hexdigest(),
        )
        self.assertEqual(
            copied_module.LOADED_MODULE_CODE_SHA256,
            loaded_code_digest,
        )
        self.assertNotEqual(loaded_code_digest, observed_source.source_file_sha256)

    def test_each_path_record_carries_complete_run_and_source_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            raw_audited_path = (
                os.fsencode(temporary_directory) + b"/filename_with_non_utf8_byte_\xff"
            )
            file_descriptor = os.open(
                raw_audited_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(file_descriptor)
            audited_path = os.fsdecode(raw_audited_path)
            expected_lstat_metadata = os.lstat(audited_path)

            completed_command = run_audit_tool_command(
                "--include-nonmatching-records",
                "--capability",
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                audited_path,
            )

        self.assertEqual(completed_command.returncode, 0)
        self.assertEqual(completed_command.stderr, b"")
        self.assertTrue(completed_command.stdout.isascii())
        decoded_records = [
            json.loads(line)
            for line in completed_command.stdout.decode("ascii").splitlines()
        ]
        self.assertEqual(
            [record["record_type"] for record in decoded_records],
            [
                "audit_run_provenance",
                "filesystem_path_capability_assessment",
                "audit_run_completion",
            ],
        )

        run_provenance = decoded_records[0]["audit_run_provenance"]
        path_record = decoded_records[1]
        self.assertEqual(
            path_record["audit_run_provenance"],
            run_provenance,
        )
        self.assertEqual(
            os.fsencode(path_record["audited_path"]),
            raw_audited_path,
        )
        serialized_lstat_metadata = path_record["audited_path_lstat_metadata"]
        self.assertEqual(
            serialized_lstat_metadata["device_number"],
            expected_lstat_metadata.st_dev,
        )
        self.assertEqual(
            serialized_lstat_metadata["inode_number"],
            expected_lstat_metadata.st_ino,
        )
        self.assertEqual(
            serialized_lstat_metadata["permission_bits_octal"],
            "0o0600",
        )
        self.assertEqual(
            serialized_lstat_metadata["owner_user_id"],
            expected_lstat_metadata.st_uid,
        )
        self.assertEqual(
            serialized_lstat_metadata["owner_group_id"],
            expected_lstat_metadata.st_gid,
        )
        self.assertEqual(
            path_record["record_schema_id"],
            audit_under_test.STRUCTURED_RECORD_SCHEMA_ID,
        )
        self.assertEqual(
            run_provenance["selected_capabilities"],
            [audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE],
        )
        self.assertEqual(
            run_provenance["selected_capability_operation_definitions"],
            {
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE: (
                    audit_under_test.CAPABILITY_OPERATION_DEFINITION_BY_NAME[
                        audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
                    ]
                )
            },
        )
        self.assertEqual(
            run_provenance["audit_scope"]["home_directory_discovery"],
            {
                "performed": False,
                "reason": "not_required_by_configured_scan_scope",
            },
        )
        self.assertEqual(
            run_provenance["audit_scope"]["temporary_directory_discovery"],
            {
                "performed": False,
                "reason": "not_required_by_configured_scan_scope",
            },
        )
        uuid.UUID(run_provenance["audit_run_id"])
        self.assertTrue(run_provenance["audit_started_at_utc"].endswith("Z"))
        self.assertTrue(path_record["path_assessment_completed_at_utc"].endswith("Z"))
        self.assertEqual(
            run_provenance["process_credentials"]["filesystem_identifier_source_path"],
            audit_under_test.LINUX_CURRENT_THREAD_STATUS_SOURCE_PATH,
        )
        self.assertIsInstance(
            run_provenance["process_credentials"]["filesystem_user_id"],
            int,
        )
        self.assertIsInstance(
            run_provenance["process_credentials"]["filesystem_group_id"],
            int,
        )
        self.assertEqual(
            run_provenance["report_output_configuration"]["report_transport"],
            "standard_output",
        )
        self.assertIn(
            "source_file_change_time_nanoseconds",
            run_provenance["observed_tool_source_file"],
        )
        self.assertEqual(
            run_provenance["observed_tool_source_file"]["source_file_sha256"],
            hashlib.sha256(AUDIT_SCRIPT_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            run_provenance["loaded_module_code"]["identity_kind"],
            "sha256_of_marshaled_executing_module_code_object",
        )
        self.assertRegex(
            run_provenance["loaded_module_code"]["sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertEqual(
            run_provenance["observed_tool_source_file"][
                "relationship_to_loaded_code"
            ],
            "observed_path_snapshot_not_execution_identity",
        )

    def test_a_report_without_emitted_paths_still_names_its_run(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            excluded_path = Path(temporary_directory) / "excluded"
            excluded_path.write_bytes(b"not emitted")
            completed_command = run_audit_tool_command(
                "--exclude",
                str(excluded_path),
                str(excluded_path),
            )

        decoded_records = [
            json.loads(line)
            for line in completed_command.stdout.decode("ascii").splitlines()
        ]
        self.assertEqual(completed_command.returncode, 0)
        self.assertEqual(len(decoded_records), 2)
        self.assertEqual(
            decoded_records[0]["record_type"],
            "audit_run_provenance",
        )
        self.assertEqual(
            decoded_records[1]["record_type"],
            "audit_run_completion",
        )
        self.assertTrue(decoded_records[1]["audit_algorithm_completed"])

    def test_invalid_utf8_path_bytes_have_reversible_json_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            raw_path = os.fsencode(temporary_directory) + b"/bad-\xff"
            file_descriptor = os.open(
                raw_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(file_descriptor)
            decoded_path = os.fsdecode(raw_path)

            completed_command = run_audit_tool_command(
                "--full-audit",
                decoded_path,
            )

        self.assertEqual(completed_command.returncode, 0, completed_command.stderr)
        path_record = path_assessment_records_from_jsonl(completed_command.stdout)[0]
        self.assertEqual(
            base64.b64decode(path_record["audited_path_bytes_base64"]),
            raw_path,
        )
        self.assertEqual(
            base64.b64decode(
                path_record["originating_scan_root_path_bytes_base64"]
            ),
            raw_path,
        )
        provenance = path_record["audit_run_provenance"]
        self.assertEqual(
            base64.b64decode(
                provenance["requested_scan_root_paths_bytes_base64"][0]
            ),
            raw_path,
        )

    def test_all_named_json_path_fields_receive_byte_representations(self) -> None:
        source = {
            "audited_path": "/tmp/a",
            "resolved_symbolic_link_target_path": "/tmp/b",
            "requested_scan_root_paths": ["/tmp/c", "/tmp/d"],
            "selected_writable_temporary_directory": "/tmp",
            "nested": {"source_path": "/proc/self/mountinfo"},
        }
        serialized = audit_under_test.add_linux_path_byte_representations(source)

        self.assertEqual(
            base64.b64decode(serialized["audited_path_bytes_base64"]),
            b"/tmp/a",
        )
        self.assertEqual(
            [
                base64.b64decode(value)
                for value in serialized["requested_scan_root_paths_bytes_base64"]
            ],
            [b"/tmp/c", b"/tmp/d"],
        )
        self.assertEqual(
            base64.b64decode(serialized["nested"]["source_path_bytes_base64"]),
            b"/proc/self/mountinfo",
        )


class ReportPublicationVerificationTests(unittest.TestCase):
    def create_report_publication(
        self,
        destination_path: Path,
        *,
        replacement_is_authorized: bool,
    ) -> audit_under_test.PrivateReportPublication:
        return audit_under_test.PrivateReportPublication(
            str(destination_path),
            audit_run_id=str(uuid.uuid4()),
            report_output_presentation=audit_under_test.OUTPUT_PRESENTATION_JSON_LINES,
            replacement_is_authorized=replacement_is_authorized,
        )

    def unpublished_report_paths(
        self,
        destination_directory: Path,
    ) -> list[Path]:
        return list(
            destination_directory.glob(
                f".{audit_under_test.AUDIT_TOOL_NAME}.*.unpublished-report."
                f"{audit_under_test.OUTPUT_PRESENTATION_JSON_LINES}.attempt-*.tmp"
            )
        )

    def test_renameat2_uses_raw_syscall_when_libc_wrapper_is_missing(self) -> None:
        if audit_under_test.linux_syscall_number("renameat2") is None:
            self.skipTest("test process ABI has no verified renameat2 mapping")
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory_file_descriptor = os.open(
                temporary_directory,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            try:
                (Path(temporary_directory) / "source").write_bytes(b"report")
                with mock.patch.object(
                    audit_under_test,
                    "_LINUX_RENAMEAT2_FUNCTION",
                    None,
                ):
                    audit_under_test.rename_linux_directory_entry_with_flags(
                        directory_file_descriptor,
                        "source",
                        directory_file_descriptor,
                        "destination",
                        audit_under_test.RENAME_NOREPLACE,
                    )
            finally:
                os.close(directory_file_descriptor)

            self.assertFalse((Path(temporary_directory) / "source").exists())
            self.assertEqual(
                (Path(temporary_directory) / "destination").read_bytes(),
                b"report",
            )

    def test_symbolic_link_scan_root_aliasing_output_is_refused_before_publication(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            destination_path = fixture_root / "report.jsonl"
            symbolic_link = fixture_root / "link"
            symbolic_link.symlink_to(destination_path.name)

            completed_command = run_audit_tool_command(
                "--full-audit",
                "--output",
                str(destination_path),
                str(symbolic_link),
            )

            self.assertEqual(
                completed_command.returncode,
                audit_under_test.EXIT_REPORT_OUTPUT_FAILED,
            )
            self.assertIn(b"scope overlaps report transport", completed_command.stderr)
            self.assertFalse(destination_path.exists())
            self.assertTrue(symbolic_link.is_symlink())
            self.assertEqual(self.unpublished_report_paths(fixture_root), [])

    def test_new_destination_validation_failure_rolls_back_visible_report(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "report.jsonl"
            publication = self.create_report_publication(
                destination_path,
                replacement_is_authorized=False,
            )

            with (
                self.assertRaises(audit_under_test.ReportPublicationError),
                mock.patch.object(
                    publication,
                    "_verify_destination_contains_created_report",
                    side_effect=audit_under_test.ReportPublicationError(
                        "simulated destination validation failure"
                    ),
                ),
                publication,
            ):
                assert publication.text_stream is not None
                publication.text_stream.write('{"complete": true}\n')

            self.assertFalse(destination_path.exists())
            self.assertFalse(publication.created_report_was_published_to_destination)
            self.assertFalse(publication.temporary_entry_contains_created_report)
            self.assertEqual(self.unpublished_report_paths(destination_directory), [])

    def test_output_parent_dot_dot_after_symlink_uses_kernel_resolution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            lexical_parent = fixture_root / "lexical"
            physical_parent = fixture_root / "physical"
            lexical_parent.mkdir()
            (physical_parent / "through-link").mkdir(parents=True)
            kernel_output_directory = physical_parent / "reports"
            lexical_output_directory = lexical_parent / "reports"
            kernel_output_directory.mkdir()
            lexical_output_directory.mkdir()
            (lexical_parent / "link").symlink_to(physical_parent / "through-link")
            audited_file = fixture_root / "audited"
            audited_file.write_bytes(b"content")
            requested_output = (
                lexical_parent / "link" / ".." / "reports" / "audit.jsonl"
            )

            completed_command = run_audit_tool_command(
                "--output",
                requested_output,
                audited_file,
            )

            self.assertEqual(completed_command.returncode, 0)
            self.assertTrue((kernel_output_directory / "audit.jsonl").is_file())
            self.assertFalse((lexical_output_directory / "audit.jsonl").exists())

    def test_exact_output_and_scan_root_overlap_is_refused_without_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            victim_path = Path(temporary_directory) / "victim"
            victim_path.write_bytes(b"ORIGINAL")

            completed_command = run_audit_tool_command(
                "--full-audit",
                "--replace-output",
                "--output",
                str(victim_path),
                str(victim_path),
            )

            self.assertEqual(
                completed_command.returncode,
                audit_under_test.EXIT_REPORT_OUTPUT_FAILED,
            )
            self.assertEqual(victim_path.read_bytes(), b"ORIGINAL")
            self.assertIn(b"must not also be an audit scan root", completed_command.stderr)
            self.assertEqual(
                self.unpublished_report_paths(Path(temporary_directory)),
                [],
            )

    def test_missing_report_parent_is_a_report_output_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            audited_file = fixture_root / "audited"
            audited_file.write_bytes(b"fixture")
            report_path = fixture_root / "missing" / "report.jsonl"

            completed_command = run_audit_tool_command(
                "--output",
                str(report_path),
                str(audited_file),
            )

        self.assertEqual(
            completed_command.returncode,
            audit_under_test.EXIT_REPORT_OUTPUT_FAILED,
        )
        self.assertIn(b"report publication failed", completed_command.stderr)

    def test_unexpected_destination_open_oserror_is_still_an_output_failure(
        self,
    ) -> None:
        diagnostic_stream = io.StringIO()
        with mock.patch.object(
            audit_under_test.PrivateReportPublication,
            "_open_destination_directory",
            side_effect=OSError(errno.EIO, "simulated destination open failure"),
        ), contextlib.redirect_stderr(diagnostic_stream):
            exit_status = audit_under_test.run_audit_command(
                (
                    "--allow-root-audit",
                    "--output",
                    "/tmp/simulated-report-output",
                    "/tmp/simulated-audit-root",
                )
            )

        self.assertEqual(
            exit_status,
            audit_under_test.EXIT_REPORT_OUTPUT_FAILED,
        )
        self.assertIn("report publication failed", diagnostic_stream.getvalue())

    @unittest.skipIf(
        os.geteuid() == 0,
        "directory read-permission fixture requires an unprivileged identity",
    )
    def test_write_search_only_report_parent_has_documented_output_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            audited_file = fixture_root / "audited"
            audited_file.write_bytes(b"fixture")
            report_directory = fixture_root / "write-search-only"
            report_directory.mkdir(mode=0o300)
            report_path = report_directory / "report.jsonl"
            try:
                completed_command = run_audit_tool_command(
                    "--output",
                    str(report_path),
                    str(audited_file),
                )
            finally:
                report_directory.chmod(0o700)

        self.assertEqual(
            completed_command.returncode,
            audit_under_test.EXIT_REPORT_OUTPUT_FAILED,
        )
        self.assertIn(b"destination parent directory", completed_command.stderr)

    def test_new_report_is_private_unpublished_then_atomically_named(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "audit-report.jsonl"
            publication = self.create_report_publication(
                destination_path,
                replacement_is_authorized=False,
            )

            with publication:
                self.assertFalse(destination_path.exists())
                unpublished_path = Path(publication.unpublished_report_path or "")
                self.assertTrue(unpublished_path.exists())
                self.assertEqual(
                    stat.S_IMODE(unpublished_path.stat().st_mode),
                    0o600,
                )
                self.assertIn(
                    publication.audit_run_id,
                    unpublished_path.name,
                )
                self.assertIn("unpublished-report", unpublished_path.name)
                self.assertIn(
                    audit_under_test.OUTPUT_PRESENTATION_JSON_LINES,
                    unpublished_path.name,
                )
                self.assertTrue(unpublished_path.name.endswith(".tmp"))
                assert publication.text_stream is not None
                publication.text_stream.write('{"complete": true}\n')

            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                '{"complete": true}\n',
            )
            self.assertEqual(
                stat.S_IMODE(destination_path.stat().st_mode),
                0o600,
            )
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_non_sticky_shared_output_directory_is_refused_before_creation(
        self,
    ) -> None:
        for shared_mode in (0o770, 0o707):
            with (
                self.subTest(shared_mode=oct(shared_mode)),
                tempfile.TemporaryDirectory() as temporary_directory,
            ):
                destination_directory = Path(temporary_directory)
                destination_directory.chmod(shared_mode)
                destination_path = destination_directory / "report.jsonl"

                with self.assertRaisesRegex(
                    audit_under_test.ReportPublicationError,
                    "non-sticky group/other-writable",
                ):
                    with self.create_report_publication(
                        destination_path,
                        replacement_is_authorized=False,
                    ):
                        self.fail("unsafe output directory must be refused")

                self.assertFalse(destination_path.exists())
                self.assertEqual(
                    self.unpublished_report_paths(destination_directory),
                    [],
                )

    def test_sticky_shared_output_directory_remains_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_directory.chmod(0o1777)
            destination_path = destination_directory / "report.jsonl"

            with self.create_report_publication(
                destination_path,
                replacement_is_authorized=False,
            ) as publication:
                assert publication.text_stream is not None
                publication.text_stream.write("complete\n")

            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                "complete\n",
            )
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_existing_destination_requires_explicit_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "report.jsonl"
            destination_path.write_text(
                "existing report\n",
                encoding="utf-8",
            )

            with (
                self.assertRaises(audit_under_test.ReportPublicationError),
                self.create_report_publication(
                    destination_path,
                    replacement_is_authorized=False,
                ),
            ):
                self.fail("existing destination must be refused")

            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                "existing report\n",
            )
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_exchange_ctime_change_does_not_hide_other_metadata_changes(
        self,
    ) -> None:
        observation_before_exchange = audit_under_test.ReportDestinationObservation(
            filesystem_identity=audit_under_test.FilesystemObjectIdentity(10, 20),
            inode_change_time_nanoseconds=100,
            content_modification_time_nanoseconds=90,
            file_size_bytes=12,
            permission_and_type_mode=stat.S_IFREG | 0o600,
            owner_user_id=1000,
            owner_group_id=1000,
            hard_link_count=1,
        )
        observation_after_exchange = replace(
            observation_before_exchange,
            inode_change_time_nanoseconds=101,
        )

        self.assertTrue(
            observation_after_exchange.matches_after_directory_entry_exchange(
                observation_before_exchange
            )
        )
        self.assertFalse(
            replace(
                observation_after_exchange,
                owner_user_id=1001,
            ).matches_after_directory_entry_exchange(observation_before_exchange)
        )
        self.assertFalse(
            replace(
                observation_after_exchange,
                inode_change_time_nanoseconds=99,
            ).matches_after_directory_entry_exchange(observation_before_exchange)
        )

    def test_authorized_replacement_preserves_old_report_until_exit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "report.jsonl"
            destination_path.write_text("old\n", encoding="utf-8")
            publication = self.create_report_publication(
                destination_path,
                replacement_is_authorized=True,
            )

            with publication:
                self.assertEqual(
                    destination_path.read_text(encoding="utf-8"),
                    "old\n",
                )
                assert publication.text_stream is not None
                publication.text_stream.write('{"new": true}\n')

            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                '{"new": true}\n',
            )
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_exchange_directory_fsync_failure_restores_old_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "report.jsonl"
            destination_path.write_text("old\n", encoding="utf-8")
            publication = self.create_report_publication(
                destination_path,
                replacement_is_authorized=True,
            )

            with (
                self.assertRaises(audit_under_test.ReportPublicationError),
                mock.patch.object(
                    publication,
                    "_synchronize_destination_directory",
                    side_effect=OSError(errno.EIO, "simulated directory fsync failure"),
                ),
                publication,
            ):
                assert publication.text_stream is not None
                publication.text_stream.write("new\n")

            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                "old\n",
            )
            self.assertFalse(publication.created_report_was_published_to_destination)
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_final_directory_fsync_failure_reports_partial_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "report.jsonl"
            destination_path.write_text("old\n", encoding="utf-8")
            publication = self.create_report_publication(
                destination_path,
                replacement_is_authorized=True,
            )
            synchronize_normally = publication._synchronize_destination_directory
            synchronization_count = 0

            def fail_second_directory_synchronization():
                nonlocal synchronization_count
                synchronization_count += 1
                if synchronization_count == 2:
                    raise OSError(
                        errno.EIO,
                        "simulated final directory fsync failure",
                    )
                synchronize_normally()

            with (
                self.assertRaises(
                    audit_under_test.ReportPublicationPartiallyCompletedError
                ),
                mock.patch.object(
                    publication,
                    "_synchronize_destination_directory",
                    side_effect=fail_second_directory_synchronization,
                ),
                publication,
            ):
                assert publication.text_stream is not None
                publication.text_stream.write("new\n")

            self.assertEqual(synchronization_count, 2)
            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                "new\n",
            )
            self.assertTrue(publication.created_report_was_published_to_destination)
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_command_diagnostic_distinguishes_partial_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            audited_file = fixture_root / "audited"
            audited_file.write_bytes(b"fixture")
            destination_path = fixture_root / "report.jsonl"

            with mock.patch.object(
                audit_under_test.PrivateReportPublication,
                "_synchronize_destination_directory",
                side_effect=OSError(errno.EIO, "simulated directory fsync failure"),
            ):
                diagnostic_stream = io.StringIO()
                with contextlib.redirect_stderr(diagnostic_stream):
                    exit_status = audit_under_test.run_audit_command(
                        (
                            "--allow-root-audit",
                            "--output",
                            str(destination_path),
                            str(audited_file),
                        )
                    )

            self.assertEqual(
                exit_status,
                audit_under_test.EXIT_REPORT_OUTPUT_FAILED,
            )
            self.assertTrue(destination_path.is_file())
            self.assertIn(
                "report publication partially completed",
                diagnostic_stream.getvalue(),
            )

    def test_exception_removes_unpublished_report_and_preserves_destination(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "report.jsonl"
            destination_path.write_text("old\n", encoding="utf-8")

            with (
                self.assertRaisesRegex(RuntimeError, "simulated audit"),
                self.create_report_publication(
                    destination_path,
                    replacement_is_authorized=True,
                ) as publication,
            ):
                assert publication.text_stream is not None
                publication.text_stream.write("partial\n")
                raise RuntimeError("simulated audit failure")

            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                "old\n",
            )
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_interruption_during_exchange_validation_restores_destination(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "report.jsonl"
            destination_path.write_text("observed report\n", encoding="utf-8")
            publication = self.create_report_publication(
                destination_path,
                replacement_is_authorized=True,
            )

            with (
                self.assertRaises(KeyboardInterrupt),
                mock.patch.object(
                    publication,
                    "_verify_destination_contains_created_report",
                    side_effect=KeyboardInterrupt,
                ),
                publication,
            ):
                assert publication.text_stream is not None
                publication.text_stream.write('{"new": true}\n')

            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                "observed report\n",
            )
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_interruption_after_displaced_report_removal_keeps_published_report(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "report.jsonl"
            destination_path.write_text("observed report\n", encoding="utf-8")
            publication = self.create_report_publication(
                destination_path,
                replacement_is_authorized=True,
            )
            unlink_then_interrupt = audit_under_test.os.unlink

            def remove_displaced_entry_then_interrupt(
                entry_name: str,
                *,
                dir_fd: int,
            ) -> None:
                unlink_then_interrupt(entry_name, dir_fd=dir_fd)
                raise KeyboardInterrupt

            with (
                self.assertRaises(KeyboardInterrupt),
                mock.patch.object(
                    audit_under_test.os,
                    "unlink",
                    side_effect=remove_displaced_entry_then_interrupt,
                ),
                publication,
            ):
                assert publication.text_stream is not None
                publication.text_stream.write('{"new": true}\n')

            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                '{"new": true}\n',
            )
            self.assertTrue(
                publication.created_report_was_published_to_destination,
            )
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_destination_created_during_audit_is_not_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "report.jsonl"

            with (
                self.assertRaises(audit_under_test.ReportPublicationError),
                self.create_report_publication(
                    destination_path,
                    replacement_is_authorized=True,
                ) as publication,
            ):
                assert publication.text_stream is not None
                publication.text_stream.write('{"new": true}\n')
                destination_path.write_text(
                    "concurrent\n",
                    encoding="utf-8",
                )

            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                "concurrent\n",
            )
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_destination_changed_during_audit_is_not_replaced(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            destination_path = destination_directory / "report.jsonl"
            destination_path.write_text("initial\n", encoding="utf-8")

            with (
                self.assertRaises(audit_under_test.ReportPublicationError),
                self.create_report_publication(
                    destination_path,
                    replacement_is_authorized=True,
                ) as publication,
            ):
                assert publication.text_stream is not None
                publication.text_stream.write('{"new": true}\n')
                destination_path.write_text(
                    "concurrently changed destination\n",
                    encoding="utf-8",
                )

            self.assertEqual(
                destination_path.read_text(encoding="utf-8"),
                "concurrently changed destination\n",
            )
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_symlink_and_named_pipe_destinations_are_refused(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination_directory = Path(temporary_directory)
            symlink_target = destination_directory / "target"
            symlink_target.write_text("target content\n", encoding="utf-8")
            symlink_destination = destination_directory / "report-symlink"
            symlink_destination.symlink_to(symlink_target)
            named_pipe_destination = destination_directory / "report-pipe"
            os.mkfifo(named_pipe_destination, 0o600)

            for refused_destination in (
                symlink_destination,
                named_pipe_destination,
            ):
                with (
                    self.subTest(destination=refused_destination.name),
                    self.assertRaises(audit_under_test.ReportPublicationError),
                    self.create_report_publication(
                        refused_destination,
                        replacement_is_authorized=True,
                    ),
                ):
                    self.fail("non-regular destination must be refused")

            self.assertEqual(
                symlink_target.read_text(encoding="utf-8"),
                "target content\n",
            )
            self.assertTrue(named_pipe_destination.exists())
            self.assertEqual(
                self.unpublished_report_paths(destination_directory),
                [],
            )

    def test_active_report_artifacts_are_omitted_and_do_not_change_tree_deletion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_directory = Path(temporary_directory) / "audited"
            audited_directory.mkdir()
            ordinary_child = audited_directory / "ordinary-child"
            ordinary_child.write_bytes(b"ordinary")
            report_path = audited_directory / "permission-audit.jsonl"

            completed_command = run_audit_tool_command(
                "--include-nonmatching-records",
                "--capability",
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                "--output",
                str(report_path),
                str(audited_directory),
            )

            self.assertEqual(completed_command.returncode, 0)
            decoded_records = [
                json.loads(line)
                for line in report_path.read_text(encoding="utf-8").splitlines()
            ]
            path_records = [
                record
                for record in decoded_records
                if record["record_type"] == "filesystem_path_capability_assessment"
            ]
            audited_paths = {record["audited_path"] for record in path_records}
            self.assertNotIn(str(report_path), audited_paths)
            self.assertFalse(
                any(
                    "unpublished-report" in audited_path
                    for audited_path in audited_paths
                )
            )
            audited_directory_record = next(
                record
                for record in path_records
                if record["audited_path"] == str(audited_directory)
            )
            self.assertIn(
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                audited_directory_record["model_indicated_capabilities"],
            )

    def test_report_inside_and_outside_tree_produce_same_root_delete_inference(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture_root = Path(temporary_directory)
            roots = [fixture_root / "inside-case", fixture_root / "outside-case"]
            for root in roots:
                root.mkdir()
                (root / "ordinary-child").write_bytes(b"ordinary")
            inside_report = roots[0] / "report.jsonl"
            outside_report = fixture_root / "outside-report.jsonl"

            inside_command = run_audit_tool_command(
                "--full-audit",
                "--capability",
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                "--output",
                str(inside_report),
                str(roots[0]),
            )
            outside_command = run_audit_tool_command(
                "--full-audit",
                "--capability",
                audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                "--output",
                str(outside_report),
                str(roots[1]),
            )

            self.assertEqual(inside_command.returncode, 0, inside_command.stderr)
            self.assertEqual(outside_command.returncode, 0, outside_command.stderr)

            def root_delete_fields(report_path: Path, root_path: Path):
                records = [
                    json.loads(line)
                    for line in report_path.read_text(encoding="utf-8").splitlines()
                ]
                record = next(
                    item
                    for item in records
                    if item.get("audited_path") == str(root_path)
                )
                return (
                    record["model_status"],
                    record["model_indicated_capabilities"],
                    record["model_blocked_capabilities"],
                    record.get("capabilities_with_insufficient_evidence", {}),
                )

            self.assertEqual(
                root_delete_fields(inside_report, roots[0]),
                root_delete_fields(outside_report, roots[1]),
            )


@unittest.skipUnless(shutil.which("strace"), "strace is unavailable")
class StraceReadOnlySmokeTest(unittest.TestCase):
    def test_stdout_mode_has_no_explicit_target_mutation_syscalls(self) -> None:
        with tempfile.TemporaryDirectory() as target_directory:  # noqa: SIM117
            with tempfile.TemporaryDirectory() as trace_directory:
                target = Path(target_directory)
                target_file = target / "fixture"
                target_file.write_bytes(b"immutable test payload")
                original_mode = stat.S_IMODE(target_file.stat().st_mode)
                trace_path = Path(trace_directory) / "trace.log"

                environment = os.environ.copy()
                environment["PYTHONDONTWRITEBYTECODE"] = "1"
                completed = subprocess.run(
                    [
                        "strace",
                        "-qq",
                        "-f",
                        "-e",
                        "trace=%file",
                        "-o",
                        str(trace_path),
                        sys.executable,
                        str(AUDIT_SCRIPT_PATH),
                        "--allow-root-audit",
                        "--include-nonmatching-records",
                        "--json",
                        str(target),
                    ],
                    capture_output=True,
                    env=environment,
                    timeout=30,
                    check=False,
                )
                if completed.returncode != 0 and (
                    b"Operation not permitted" in completed.stderr
                    or b"ptrace" in completed.stderr
                ):
                    self.skipTest("ptrace is blocked in this environment")

                self.assertEqual(completed.returncode, 0, completed.stderr)
                mutating_syscall_names = (
                    "creat(",
                    "unlink(",
                    "unlinkat(",
                    "rename(",
                    "renameat(",
                    "renameat2(",
                    "mkdir(",
                    "mkdirat(",
                    "rmdir(",
                    "chmod(",
                    "fchmodat(",
                    "chown(",
                    "lchown(",
                    "truncate(",
                )
                mutating_open_flags = (
                    "O_WRONLY",
                    "O_RDWR",
                    "O_CREAT",
                    "O_TRUNC",
                    "O_APPEND",
                )
                relevant_lines = [
                    line
                    for line in trace_path.read_text(
                        encoding="utf-8",
                        errors="replace",
                    ).splitlines()
                    if target_directory in line
                ]
                for line in relevant_lines:
                    self.assertFalse(
                        any(name in line for name in mutating_syscall_names),
                        line,
                    )
                    self.assertFalse(
                        any(flag in line for flag in mutating_open_flags),
                        line,
                    )

                self.assertEqual(target_file.read_bytes(), b"immutable test payload")
                self.assertEqual(
                    stat.S_IMODE(target_file.stat().st_mode),
                    original_mode,
                )
                self.assertEqual(
                    sorted(path.name for path in target.iterdir()),
                    ["fixture"],
                )

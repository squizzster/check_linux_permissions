"""Executable assertions for the standalone tool's present contract."""

from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
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
                    self.assertEqual(
                        read_only_assessment.inference_for_capability(
                            audit_under_test.CAPABILITY_APPEND_REGULAR_FILE_CONTENT
                        ).model_verdict,
                        audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED,
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
                        audit_under_test.MODEL_VERDICT_INDICATES_BLOCKED,
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
            excluded_child = fixture_root / "excluded_child"
            excluded_child.write_bytes(b"excluded")
            exclusion_rule = audit_under_test.PathExclusionRule(
                excluded_path=str(excluded_child),
                includes_descendants=False,
                rule_origin="test",
            )
            active_auditor = permission_auditor(exclusion_rules=(exclusion_rule,))
            partial_listing = audit_under_test.DirectoryListingEvidence(
                child_paths=(str(excluded_child),),
                listing_failure=audit_under_test.EvidenceReason(
                    "simulated_partial_directory_read",
                    evidence_source="test",
                ),
                observation_notes=(),
            )

            with (
                mock.patch.object(
                    active_auditor,
                    "_read_directory_child_paths",
                    return_value=partial_listing,
                ),
                inode_attributes_observed_clear(),
            ):
                root_assessment = list(
                    active_auditor.assess_path_tree(
                        str(fixture_root),
                        selected_capabilities=(
                            audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE,
                        ),
                    )
                )[-1]

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


class EvidenceUncertaintyVerificationTests(unittest.TestCase):
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

    def test_unreported_statx_attribute_bits_are_explicitly_uncertain(
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

        self.assertIsNone(pre_statx_verity_evidence.immutable_attribute_is_set)
        self.assertIsNone(pre_statx_verity_evidence.append_only_attribute_is_set)
        self.assertIsNone(pre_statx_verity_evidence.verity_attribute_is_set)
        self.assertEqual(
            pre_statx_verity_evidence.verity_uncertainty_reason.reason_code,
            "running_kernel_predates_documented_statx_verity_reporting",
        )
        self.assertEqual(
            {
                reason.reason_code
                for reason in pre_statx_verity_evidence.uncertainty_reasons
            },
            {
                "filesystem_did_not_report_immutable_attribute_support",
                "filesystem_did_not_report_append_only_attribute_support",
            },
        )

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
    def test_child_metadata_failures_become_path_and_parent_uncertainty(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            audited_directory = Path(temporary_directory) / "audited"
            audited_directory.mkdir()
            child_path = audited_directory / "child"
            child_path.write_bytes(b"child")
            real_lstat = audit_under_test.os.lstat

            for simulated_error, expected_kind, expected_reason_code in (
                (
                    FileNotFoundError(errno.ENOENT, "simulated disappearance"),
                    audit_under_test.FILESYSTEM_OBJECT_KIND_MISSING,
                    "path_disappeared_during_directory_scan",
                ),
                (
                    PermissionError(errno.EACCES, "simulated metadata denial"),
                    audit_under_test.FILESYSTEM_OBJECT_KIND_UNOBSERVED,
                    "cannot_observe_path_metadata",
                ),
            ):
                with self.subTest(reason_code=expected_reason_code):

                    def lstat_with_child_failure(
                        path,
                        simulated_child_error=simulated_error,
                    ):
                        if str(path) == str(child_path):
                            raise simulated_child_error
                        return real_lstat(path)

                    with (
                        mock.patch.object(
                            audit_under_test.os,
                            "lstat",
                            side_effect=lstat_with_child_failure,
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
                directory_path: str,
            ) -> audit_under_test.OpenDirectoryForListingEvidence:
                normal_open_evidence = open_directory_normally(directory_path)
                return audit_under_test.OpenDirectoryForListingEvidence(
                    directory_file_descriptor=(
                        normal_open_evidence.directory_file_descriptor
                    ),
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
                "directory_identity_changed_between_lstat_and_open",
                {reason.reason_code for reason in inference.evidence_reasons},
            )

    def test_child_order_is_stable_for_arbitrary_linux_filename_bytes(
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
        self.assertEqual(
            observed_child_name_bytes,
            sorted(child_names),
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
            "[daocs] /scope/link\\nname -> /target/directory/\n",
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


class JsonlEvidenceContractTests(unittest.TestCase):
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
        self.assertEqual(len(decoded_records), 1)
        self.assertEqual(
            decoded_records[0]["record_type"],
            "audit_run_provenance",
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

    def test_destination_changed_during_audit_is_exchanged_back(
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

    def test_active_report_artifacts_are_omitted_and_block_tree_deletion(
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
            delete_reason_codes = {
                reason["reason_code"]
                for reason in audited_directory_record["model_blocked_capabilities"][
                    audit_under_test.CAPABILITY_DELETE_ENTRY_OR_TREE
                ]
            }
            self.assertIn(
                "at_least_one_descendant_would_remain",
                delete_reason_codes,
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

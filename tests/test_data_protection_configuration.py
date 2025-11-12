# test_data_protection_configuration.py
# This class tests the DataProtectionConfiguration service class

# import json
import os
import sys
import pytest

# Authentication via the test_authorization.py
from tests import test_authorization as Authorization

# Import our sibling src folder into the path
sys.path.append(os.path.abspath('src'))
# Classes to test - manually imported from sibling folder
from falconpy import DataProtectionConfiguration

auth = Authorization.TestAuthorization()
config = auth.getConfigObject()
falcon = DataProtectionConfiguration(auth_object=config)
AllowedResponses = [200, 201, 207, 400, 403, 404, 429]


class TestDataProtectionConfiguration:
    @pytest.mark.skipif(config.base_url == "https://api.laggar.gcw.crowdstrike.com",
                        reason="Unit testing unavailable on US-GOV-1"
                        )
    def test_all_code_paths(self):
        error_checks = True
        tests = {
            # Classification methods
            "entities_classification_get_v2": falcon.get_classification(ids="test-id"),
            "entities_classification_post_v2": falcon.create_classification(body={}),
            "entities_classification_patch_v2": falcon.update_classifications(body={}),
            "entities_classification_delete_v2": falcon.delete_classification(ids="test-id"),
            
            # Cloud application methods
            "entities_cloud_application_get": falcon.get_cloud_application(ids="test-id"),
            "entities_cloud_application_create": falcon.create_cloud_application(body={}),
            "entities_cloud_application_patch": falcon.update_cloud_application(id="test-id", body={}),
            "entities_cloud_application_delete": falcon.delete_cloud_application(ids="test-id"),
            
            # Content pattern methods
            "entities_content_pattern_get": falcon.get_content_pattern(ids="test-id"),
            "entities_content_pattern_create": falcon.create_content_pattern(body={}),
            "entities_content_pattern_patch": falcon.update_content_pattern(id="test-id", body={}),
            "entities_content_pattern_delete": falcon.delete_content_pattern(ids="test-id"),
            
            # Enterprise account methods
            "entities_enterprise_account_get": falcon.get_enterprise_account(ids="test-id"),
            "entities_enterprise_account_create": falcon.create_enterprise_account(body={}),
            "entities_enterprise_account_patch": falcon.update_enterprise_account(body={}),
            "entities_enterprise_account_delete": falcon.delete_enterprise_account(ids="test-id"),
            
            # File type methods
            "entities_file_type_get": falcon.get_file_type(ids="test-id"),
            
            # Sensitivity label methods
            "entities_sensitivity_label_get_v2": falcon.get_sensitivity_label(ids="test-id"),
            "entities_sensitivity_label_create_v2": falcon.create_sensitivity_label(body={}),
            "entities_sensitivity_label_delete_v2": falcon.delete_sensitivity_label(ids="test-id"),
            
            # Policy methods
            "entities_policy_get_v2": falcon.get_policies(ids="test-id"),
            "entities_policy_post_v2": falcon.create_policy(platform_name="win", body={}),
            "entities_policy_patch_v2": falcon.update_policies(platform_name="win", body={}),
            "entities_policy_delete_v2": falcon.delete_policies(ids="test-id", platform_name="win"),
            
            # Web location methods
            "entities_web_location_get_v2": falcon.get_web_location(ids="test-id"),
            "entities_web_location_create_v2": falcon.create_web_location(body={}),
            "entities_web_location_patch_v2": falcon.update_web_location(id="test-id", body={}),
            "entities_web_location_delete_v2": falcon.delete_web_location(ids="test-id"),
            
            # Query methods
            "queries_classification_get_v2": falcon.query_classifications(),
            "queries_cloud_application_get_v2": falcon.query_cloud_applications(),
            "queries_content_pattern_get_v2": falcon.query_content_patterns(),
            "queries_enterprise_account_get_v2": falcon.query_enterprise_accounts(),
            "queries_file_type_get_v2": falcon.query_file_type(),
            "queries_sensitivity_label_get_v2": falcon.query_sensitivity_label(),
            "queries_policy_get_v2": falcon.query_policies(platform_name="win"),
            "queries_web_location_get_v2": falcon.query_web_locations(),
        }
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(key)
                print(tests[key])
        assert error_checks

    def test_classification_with_keywords(self):
        """Test classification methods using keyword arguments."""
        error_checks = True
        tests = {
            "get_classification_keywords": falcon.get_classification(ids=["test-id-1", "test-id-2"]),
            "create_classification_keywords": falcon.create_classification(
                resources=[{
                    "name": "test-classification",
                    "classification_properties": {
                        "protection_mode": "monitor",
                        "evidence_duplication_enabled": True,
                        "content_patterns": ["pattern1"],
                        "file_types": ["doc", "pdf"],
                        "sensitivity_labels": ["label1"],
                        "web_sources": ["source1"],
                        "rules": [{
                            "description": "test rule",
                            "detection_severity": "informational",
                            "response_action": "allow",
                            "user_scope": "all",
                            "trigger_detection": True,
                            "notify_end_user": True,
                            "enable_printer_egress": True,
                            "enable_usb_devices": True,
                            "enable_web_locations": True,
                            "web_locations_scope": "all"
                        }]
                    }
                }]
            ),
            "update_classifications_keywords": falcon.update_classifications(
                resources=[{
                    "name": "updated-classification",
                    "classification_properties": {
                        "protection_mode": "block",
                        "evidence_duplication_enabled": False
                    }
                }]
            ),
            "delete_classification_keywords": falcon.delete_classification(ids=["test-id-1"])
        }
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(key)
                print(tests[key])
        assert error_checks

    def test_cloud_application_with_keywords(self):
        """Test cloud application methods using keyword arguments."""
        error_checks = True
        tests = {
            "get_cloud_application_keywords": falcon.get_cloud_application(ids=["app-id-1", "app-id-2"]),
            "create_cloud_application_keywords": falcon.create_cloud_application(
                name="test-app",
                description="Test cloud application",
                urls=[{
                    "fqdn": "example.com",
                    "path": "/api"
                }]
            ),
            "update_cloud_application_keywords": falcon.update_cloud_application(
                id="app-id-1",
                name="updated-app",
                description="Updated cloud application"
            ),
            "delete_cloud_application_keywords": falcon.delete_cloud_application(ids=["app-id-1"])
        }
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(key)
                print(tests[key])
        assert error_checks

    def test_content_pattern_with_keywords(self):
        """Test content pattern methods using keyword arguments."""
        error_checks = True
        tests = {
            "get_content_pattern_keywords": falcon.get_content_pattern(ids=["pattern-id-1", "pattern-id-2"]),
            "create_content_pattern_keywords": falcon.create_content_pattern(
                name="test-pattern",
                description="Test content pattern",
                category="pii",
                region="us",
                min_match_threshold=1,
                example="123-45-6789",
                regexes=[r"\d{3}-\d{2}-\d{4}"]
            ),
            "update_content_pattern_keywords": falcon.update_content_pattern(
                id="pattern-id-1",
                name="updated-pattern",
                description="Updated content pattern"
            ),
            "delete_content_pattern_keywords": falcon.delete_content_pattern(ids=["pattern-id-1"])
        }
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(key)
                print(tests[key])
        assert error_checks

    def test_enterprise_account_with_keywords(self):
        """Test enterprise account methods using keyword arguments."""
        error_checks = True
        tests = {
            "get_enterprise_account_keywords": falcon.get_enterprise_account(ids=["account-id-1", "account-id-2"]),
            "create_enterprise_account_keywords": falcon.create_enterprise_account(body={}),
            "update_enterprise_account_keywords": falcon.update_enterprise_account(id="account-id-1", body={}),
            "delete_enterprise_account_keywords": falcon.delete_enterprise_account(ids=["account-id-1"])
        }
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(key)
                print(tests[key])
        assert error_checks

    def test_sensitivity_label_with_keywords(self):
        """Test sensitivity label methods using keyword arguments."""
        error_checks = True
        tests = {
            "get_sensitivity_label_keywords": falcon.get_sensitivity_label(ids=["label-id-1", "label-id-2"]),
            "create_sensitivity_label_keywords": falcon.create_sensitivity_label(
                name="test-label",
                display_name="Test Label",
                external_id="external-123",
                label_provider="microsoft",
                plugins_configuration_id="config-123",
                co_authoring=True,
                synced=True
            ),
            "delete_sensitivity_label_keywords": falcon.delete_sensitivity_label(ids=["label-id-1"])
        }
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(key)
                print(tests[key])
        assert error_checks

    def test_policy_with_keywords(self):
        """Test policy methods using keyword arguments."""
        error_checks = True
        tests = {
            "get_policies_keywords": falcon.get_policies(ids=["policy-id-1", "policy-id-2"]),
            "create_policy_keywords": falcon.create_policy(
                platform_name="win",
                resources=[{
                    "name": "test-policy",
                    "description": "Test data protection policy",
                    "precedence": 1,
                    "policy_properties": {
                        "allow_notifications": "default",
                        "block_notifications": "default",
                        "enable_content_inspection": True,
                        "enable_context_inspection": True,
                        "enable_network_inspection": True,
                        "enable_clipboard_inspection": True,
                        "min_confidence_level": "low",
                        "inspection_depth": "balanced",
                        "similarity_detection": True,
                        "similarity_threshold": "10",
                        "evidence_duplication_enabled_default": True,
                        "evidence_download_enabled": True,
                        "evidence_encrypted_enabled": True,
                        "classifications": ["classification-1"]
                    }
                }]
            ),
            "update_policies_keywords": falcon.update_policies(
                platform_name="win",
                resources=[{
                    "name": "updated-policy",
                    "description": "Updated data protection policy",
                    "precedence": 2
                }]
            ),
            "delete_policies_keywords": falcon.delete_policies(ids=["policy-id-1"], platform_name="win")
        }
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(key)
                print(tests[key])
        assert error_checks

    def test_web_location_with_keywords(self):
        """Test web location methods using keyword arguments."""
        error_checks = True
        tests = {
            "get_web_location_keywords": falcon.get_web_location(ids=["location-id-1", "location-id-2"]),
            "create_web_location_keywords": falcon.create_web_location(
                web_locations=[{
                    "name": "test-location",
                    "type": "custom",
                    "location_type": "url",
                    "application_id": "app-123",
                    "enterprise_account_id": "account-123"
                }]
            ),
            "update_web_location_keywords": falcon.update_web_location(
                id="location-id-1",
                web_locations=[{
                    "name": "updated-location",
                    "type": "custom"
                }]
            ),
            "delete_web_location_keywords": falcon.delete_web_location(ids=["location-id-1"])
        }
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(key)
                print(tests[key])
        assert error_checks

    def test_query_methods_with_filters(self):
        """Test query methods with various filter parameters."""
        error_checks = True
        tests = {
            "query_classifications_with_filter": falcon.query_classifications(
                filter="name:'test'",
                limit=10,
                offset=0,
                sort="name"
            ),
            "query_cloud_applications_with_filter": falcon.query_cloud_applications(
                filter="name:'test'",
                sort="name",
                limit=50,
                offset=0
            ),
            "query_content_patterns_with_filter": falcon.query_content_patterns(
                filter="category:'pii'",
                sort="name",
                limit=25,
                offset=0
            ),
            "query_enterprise_accounts_with_filter": falcon.query_enterprise_accounts(
                filter="name:'test'",
                sort="name",
                limit=100,
                offset=0
            ),
            "query_file_type_with_filter": falcon.query_file_type(
                filter="name:'pdf'",
                sort="name",
                limit=20,
                offset=0
            ),
            "query_sensitivity_label_with_filter": falcon.query_sensitivity_label(
                filter="name:'confidential'",
                sort="name",
                limit=30,
                offset=0
            ),
            "query_policies_with_filter": falcon.query_policies(
                platform_name="win",
                filter="name:'test'",
                sort="name",
                limit=40,
                offset=0
            ),
            "query_web_locations_with_filter": falcon.query_web_locations(
                filter="name:'test'",
                type="custom",
                limit=60,
                offset=0
            )
        }
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(key)
                print(tests[key])
        assert error_checks

    def test_alias_methods(self):
        """Test that all alias methods work correctly."""
        error_checks = True
        tests = {
            # Classification aliases
            "entities_classification_get_v2_alias": falcon.entities_classification_get_v2(ids="test-id"),
            "entities_classification_post_v2_alias": falcon.entities_classification_post_v2(body={}),
            "entities_classification_patch_v2_alias": falcon.entities_classification_patch_v2(body={}),
            "entities_classification_delete_v2_alias": falcon.entities_classification_delete_v2(ids="test-id"),
            
            # Cloud application aliases
            "entities_cloud_application_get_alias": falcon.entities_cloud_application_get(ids="test-id"),
            "entities_cloud_application_create_alias": falcon.entities_cloud_application_create(body={}),
            "entities_cloud_application_patch_alias": falcon.entities_cloud_application_patch(id="test-id", body={}),
            "entities_cloud_application_delete_alias": falcon.entities_cloud_application_delete(ids="test-id"),
            
            # Content pattern aliases
            "entities_content_pattern_get_alias": falcon.entities_content_pattern_get(ids="test-id"),
            "entities_content_pattern_create_alias": falcon.entities_content_pattern_create(body={}),
            "entities_content_pattern_patch_alias": falcon.entities_content_pattern_patch(id="test-id", body={}),
            "entities_content_pattern_delete_alias": falcon.entities_content_pattern_delete(ids="test-id"),
            
            # Enterprise account aliases
            "entities_enterprise_account_get_alias": falcon.entities_enterprise_account_get(ids="test-id"),
            "entities_enterprise_account_create_alias": falcon.entities_enterprise_account_create(body={}),
            "entities_enterprise_account_patch_alias": falcon.entities_enterprise_account_patch(body={}),
            "entities_enterprise_account_delete_alias": falcon.entities_enterprise_account_delete(ids="test-id"),
            
            # File type alias
            "entities_file_type_get_alias": falcon.entities_file_type_get(ids="test-id"),
            
            # Sensitivity label aliases
            "entities_sensitivity_label_get_v2_alias": falcon.entities_sensitivity_label_get_v2(ids="test-id"),
            "entities_sensitivity_label_create_v2_alias": falcon.entities_sensitivity_label_create_v2(body={}),
            "entities_sensitivity_label_delete_v2_alias": falcon.entities_sensitivity_label_delete_v2(ids="test-id"),
            
            # Policy aliases
            "entities_policy_get_v2_alias": falcon.entities_policy_get_v2(ids="test-id"),
            "entities_policy_post_v2_alias": falcon.entities_policy_post_v2(platform_name="win", body={}),
            "entities_policy_patch_v2_alias": falcon.entities_policy_patch_v2(platform_name="win", body={}),
            "entities_policy_delete_v2_alias": falcon.entities_policy_delete_v2(ids="test-id", platform_name="win"),
            
            # Web location aliases
            "entities_web_location_get_v2_alias": falcon.entities_web_location_get_v2(ids="test-id"),
            "entities_web_location_create_v2_alias": falcon.entities_web_location_create_v2(body={}),
            "entities_web_location_patch_v2_alias": falcon.entities_web_location_patch_v2(id="test-id", body={}),
            "entities_web_location_delete_v2_alias": falcon.entities_web_location_delete_v2(ids="test-id"),
            
            # Query aliases
            "queries_classification_get_v2_alias": falcon.queries_classification_get_v2(),
            "queries_cloud_application_get_v2_alias": falcon.queries_cloud_application_get_v2(),
            "queries_content_pattern_get_v2_alias": falcon.queries_content_pattern_get_v2(),
            "queries_enterprise_account_get_v2_alias": falcon.queries_enterprise_account_get_v2(),
            "queries_file_type_get_v2_alias": falcon.queries_file_type_get_v2(),
            "queries_sensitivity_label_get_v2_alias": falcon.queries_sensitivity_label_get_v2(),
            "queries_policy_get_v2_alias": falcon.queries_policy_get_v2(platform_name="win"),
            "queries_web_location_get_v2_alias": falcon.queries_web_location_get_v2()
        }
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(key)
                print(tests[key])
        assert error_checks

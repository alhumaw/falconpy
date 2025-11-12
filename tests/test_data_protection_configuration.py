"""
test_data_protection_configuration.py - This class tests the DataProtectionConfiguration service class
"""
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
AllowedResponses = [200, 201, 202, 207, 400, 401, 403, 404, 429, 500, 501]


class TestDataProtectionConfiguration:
    """
    DataProtectionConfiguration Service Class test harness
    """

    def test_query_classifications_v2(self):
        """Test query classifications endpoint"""
        assert bool(
            falcon.query_classifications(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_query_classifications_v2_alias(self):
        """Test query classifications endpoint using PascalCase alias"""
        assert bool(
            falcon.QueryClassificationsV2(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_get_classification_v2(self):
        """Test get classification endpoint"""
        # Try to get a classification ID first
        query_result = falcon.query_classifications(limit=1)
        test_id = "1234567890"  # Default fallback ID
        if query_result["status_code"] in [200, 201] and query_result.get("body", {}).get("resources"):
            test_id = query_result["body"]["resources"][0]
        
        assert bool(
            falcon.get_classification(ids=test_id)["status_code"] in AllowedResponses
        ) is True

    def test_get_classification_v2_alias(self):
        """Test get classification endpoint using PascalCase alias"""
        assert bool(
            falcon.GetClassificationV2(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_create_classification_v2(self):
        """Test create classification endpoint"""
        test_payload = {
            "resources": [{
                "name": "Test Classification",
                "classification_properties": {
                    "protection_mode": "monitor",
                    "evidence_duplication_enabled": True
                }
            }]
        }
        assert bool(
            falcon.create_classification(body=test_payload)["status_code"] in AllowedResponses
        ) is True

    def test_create_classification_v2_alias(self):
        """Test create classification endpoint using PascalCase alias"""
        test_payload = {
            "resources": [{
                "name": "Test Classification Alias",
                "classification_properties": {
                    "protection_mode": "monitor"
                }
            }]
        }
        assert bool(
            falcon.CreateClassificationV2(body=test_payload)["status_code"] in AllowedResponses
        ) is True

    def test_update_classifications_v2(self):
        """Test update classifications endpoint"""
        test_payload = {
            "resources": [{
                "name": "Updated Test Classification",
                "classification_properties": {
                    "protection_mode": "block"
                }
            }]
        }
        assert bool(
            falcon.update_classifications(body=test_payload)["status_code"] in AllowedResponses
        ) is True

    def test_update_classifications_v2_alias(self):
        """Test update classifications endpoint using PascalCase alias"""
        assert bool(
            falcon.UpdateClassificationsV2(body={})["status_code"] in AllowedResponses
        ) is True

    def test_delete_classification_v2(self):
        """Test delete classification endpoint"""
        assert bool(
            falcon.delete_classification(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_delete_classification_v2_alias(self):
        """Test delete classification endpoint using PascalCase alias"""
        assert bool(
            falcon.DeleteClassificationV2(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_query_cloud_applications_v2(self):
        """Test query cloud applications endpoint"""
        assert bool(
            falcon.query_cloud_applications(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_query_cloud_applications_v2_alias(self):
        """Test query cloud applications endpoint using PascalCase alias"""
        assert bool(
            falcon.QueryCloudApplicationsV2(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_get_cloud_application(self):
        """Test get cloud application endpoint"""
        assert bool(
            falcon.get_cloud_application(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_get_cloud_application_alias(self):
        """Test get cloud application endpoint using PascalCase alias"""
        assert bool(
            falcon.GetCloudApplication(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_create_cloud_application(self):
        """Test create cloud application endpoint"""
        test_payload = {
            "name": "Test Cloud App",
            "description": "Test description",
            "urls": [{
                "fqdn": "example.com",
                "path": "/test"
            }]
        }
        assert bool(
            falcon.create_cloud_application(body=test_payload)["status_code"] in AllowedResponses
        ) is True

    def test_create_cloud_application_alias(self):
        """Test create cloud application endpoint using PascalCase alias"""
        assert bool(
            falcon.CreateCloudApplication(body={})["status_code"] in AllowedResponses
        ) is True

    def test_update_cloud_application(self):
        """Test update cloud application endpoint"""
        assert bool(
            falcon.update_cloud_application(id="1234567890", body={})["status_code"] in AllowedResponses
        ) is True

    def test_update_cloud_application_alias(self):
        """Test update cloud application endpoint using PascalCase alias"""
        assert bool(
            falcon.UpdateCloudApplication(id="1234567890", body={})["status_code"] in AllowedResponses
        ) is True

    def test_delete_cloud_application(self):
        """Test delete cloud application endpoint"""
        assert bool(
            falcon.delete_cloud_application(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_delete_cloud_application_alias(self):
        """Test delete cloud application endpoint using PascalCase alias"""
        assert bool(
            falcon.DeleteCloudApplication(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_query_content_patterns_v2(self):
        """Test query content patterns endpoint"""
        assert bool(
            falcon.query_content_patterns(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_query_content_patterns_v2_alias(self):
        """Test query content patterns endpoint using PascalCase alias"""
        assert bool(
            falcon.QueryContentPatternsV2(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_get_content_pattern(self):
        """Test get content pattern endpoint"""
        assert bool(
            falcon.get_content_pattern(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_get_content_pattern_alias(self):
        """Test get content pattern endpoint using PascalCase alias"""
        assert bool(
            falcon.GetContentPattern(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_create_content_pattern(self):
        """Test create content pattern endpoint"""
        test_payload = {
            "name": "Test Pattern",
            "category": "test",
            "description": "Test pattern description",
            "regexes": ["test.*pattern"],
            "min_match_threshold": 1
        }
        assert bool(
            falcon.create_content_pattern(body=test_payload)["status_code"] in AllowedResponses
        ) is True

    def test_create_content_pattern_alias(self):
        """Test create content pattern endpoint using PascalCase alias"""
        assert bool(
            falcon.CreateContentPattern(body={})["status_code"] in AllowedResponses
        ) is True

    def test_update_content_pattern(self):
        """Test update content pattern endpoint"""
        assert bool(
            falcon.update_content_pattern(id="1234567890", body={})["status_code"] in AllowedResponses
        ) is True

    def test_update_content_pattern_alias(self):
        """Test update content pattern endpoint using PascalCase alias"""
        assert bool(
            falcon.UpdateContentPattern(id="1234567890", body={})["status_code"] in AllowedResponses
        ) is True

    def test_delete_content_pattern(self):
        """Test delete content pattern endpoint"""
        assert bool(
            falcon.delete_content_pattern(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_delete_content_pattern_alias(self):
        """Test delete content pattern endpoint using PascalCase alias"""
        assert bool(
            falcon.DeleteContentPattern(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_query_enterprise_accounts_v2(self):
        """Test query enterprise accounts endpoint"""
        assert bool(
            falcon.query_enterprise_accounts(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_query_enterprise_accounts_v2_alias(self):
        """Test query enterprise accounts endpoint using PascalCase alias"""
        assert bool(
            falcon.QueryEnterpriseAccountsV2(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_get_enterprise_account(self):
        """Test get enterprise account endpoint"""
        assert bool(
            falcon.get_enterprise_account(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_get_enterprise_account_alias(self):
        """Test get enterprise account endpoint using PascalCase alias"""
        assert bool(
            falcon.GetEnterpriseAccount(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_create_enterprise_account(self):
        """Test create enterprise account endpoint"""
        assert bool(
            falcon.create_enterprise_account(body={})["status_code"] in AllowedResponses
        ) is True

    def test_create_enterprise_account_alias(self):
        """Test create enterprise account endpoint using PascalCase alias"""
        assert bool(
            falcon.CreateEnterpriseAccount(body={})["status_code"] in AllowedResponses
        ) is True

    def test_update_enterprise_account(self):
        """Test update enterprise account endpoint"""
        assert bool(
            falcon.update_enterprise_account(id="1234567890", body={})["status_code"] in AllowedResponses
        ) is True

    def test_update_enterprise_account_alias(self):
        """Test update enterprise account endpoint using PascalCase alias"""
        assert bool(
            falcon.UpdateEnterpriseAccount(id="1234567890", body={})["status_code"] in AllowedResponses
        ) is True

    def test_delete_enterprise_account(self):
        """Test delete enterprise account endpoint"""
        assert bool(
            falcon.delete_enterprise_account(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_delete_enterprise_account_alias(self):
        """Test delete enterprise account endpoint using PascalCase alias"""
        assert bool(
            falcon.DeleteEnterpriseAccount(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_query_file_type_v2(self):
        """Test query file type endpoint"""
        assert bool(
            falcon.query_file_type(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_query_file_type_v2_alias(self):
        """Test query file type endpoint using PascalCase alias"""
        assert bool(
            falcon.QueryFileTypeV2(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_get_file_type(self):
        """Test get file type endpoint"""
        assert bool(
            falcon.get_file_type(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_get_file_type_alias(self):
        """Test get file type endpoint using PascalCase alias"""
        assert bool(
            falcon.GetFileType(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_query_sensitivity_label_v2(self):
        """Test query sensitivity labels endpoint"""
        assert bool(
            falcon.query_sensitivity_label(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_query_sensitivity_label_v2_alias(self):
        """Test query sensitivity labels endpoint using PascalCase alias"""
        assert bool(
            falcon.QuerySensitivityLabelV2(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_get_sensitivity_label_v2(self):
        """Test get sensitivity label endpoint"""
        assert bool(
            falcon.get_sensitivity_label(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_get_sensitivity_label_v2_alias(self):
        """Test get sensitivity label endpoint using PascalCase alias"""
        assert bool(
            falcon.GetSensitivityLabelV2(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_create_sensitivity_label_v2(self):
        """Test create sensitivity label endpoint"""
        test_payload = {
            "name": "Test Label",
            "display_name": "Test Display Name",
            "external_id": "test-ext-id",
            "label_provider": "test-provider"
        }
        assert bool(
            falcon.create_sensitivity_label(body=test_payload)["status_code"] in AllowedResponses
        ) is True

    def test_create_sensitivity_label_v2_alias(self):
        """Test create sensitivity label endpoint using PascalCase alias"""
        assert bool(
            falcon.CreateSensitivityLabelV2(body={})["status_code"] in AllowedResponses
        ) is True

    def test_delete_sensitivity_label_v2(self):
        """Test delete sensitivity label endpoint"""
        assert bool(
            falcon.delete_sensitivity_label(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_delete_sensitivity_label_v2_alias(self):
        """Test delete sensitivity label endpoint using PascalCase alias"""
        assert bool(
            falcon.DeleteSensitivityLabelV2(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_query_policies_v2(self):
        """Test query policies endpoint"""
        assert bool(
            falcon.query_policies(platform_name="win", limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_query_policies_v2_alias(self):
        """Test query policies endpoint using PascalCase alias"""
        assert bool(
            falcon.QueryPoliciesV2(platform_name="mac", limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_get_policies_v2(self):
        """Test get policies endpoint"""
        assert bool(
            falcon.get_policies(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_get_policies_v2_alias(self):
        """Test get policies endpoint using PascalCase alias"""
        assert bool(
            falcon.GetPoliciesV2(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_create_policy_v2(self):
        """Test create policy endpoint"""
        test_payload = {
            "resources": [{
                "name": "Test Policy",
                "description": "Test policy description",
                "policy_properties": {
                    "enable_content_inspection": True,
                    "protection_mode": "monitor"
                },
                "precedence": 100
            }]
        }
        assert bool(
            falcon.create_policy(platform_name="win", body=test_payload)["status_code"] in AllowedResponses
        ) is True

    def test_create_policy_v2_alias(self):
        """Test create policy endpoint using PascalCase alias"""
        assert bool(
            falcon.CreatePolicyV2(platform_name="win", body={})["status_code"] in AllowedResponses
        ) is True

    def test_update_policies_v2(self):
        """Test update policies endpoint"""
        assert bool(
            falcon.update_policies(platform_name="win", body={})["status_code"] in AllowedResponses
        ) is True

    def test_update_policies_v2_alias(self):
        """Test update policies endpoint using PascalCase alias"""
        assert bool(
            falcon.UpdatePoliciesV2(platform_name="mac", body={})["status_code"] in AllowedResponses
        ) is True

    def test_delete_policies(self):
        """Test delete policies endpoint"""
        assert bool(
            falcon.delete_policies(ids="1234567890", platform_name="win")["status_code"] in AllowedResponses
        ) is True

    def test_delete_policies_alias(self):
        """Test delete policies endpoint using PascalCase alias"""
        assert bool(
            falcon.DeletePoliciesV2(ids="1234567890", platform_name="mac")["status_code"] in AllowedResponses
        ) is True

    def test_query_web_locations_v2(self):
        """Test query web locations endpoint"""
        assert bool(
            falcon.query_web_locations(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_query_web_locations_v2_alias(self):
        """Test query web locations endpoint using PascalCase alias"""
        assert bool(
            falcon.QueryWebLocationsV2(limit=1)["status_code"] in AllowedResponses
        ) is True

    def test_get_web_location_v2(self):
        """Test get web location endpoint"""
        assert bool(
            falcon.get_web_location(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_get_web_location_v2_alias(self):
        """Test get web location endpoint using PascalCase alias"""
        assert bool(
            falcon.GetWebLocationV2(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_create_web_location_v2(self):
        """Test create web location endpoint"""
        test_payload = {
            "web_locations": [{
                "name": "Test Web Location",
                "type": "custom",
                "location_type": "url"
            }]
        }
        assert bool(
            falcon.create_web_location(body=test_payload)["status_code"] in AllowedResponses
        ) is True

    def test_create_web_location_v2_alias(self):
        """Test create web location endpoint using PascalCase alias"""
        assert bool(
            falcon.CreateWebLocationV2(body={})["status_code"] in AllowedResponses
        ) is True

    def test_update_web_location_v2(self):
        """Test update web location endpoint"""
        assert bool(
            falcon.update_web_location(id="1234567890", body={})["status_code"] in AllowedResponses
        ) is True

    def test_update_web_location_v2_alias(self):
        """Test update web location endpoint using PascalCase alias"""
        assert bool(
            falcon.UpdateWebLocationV2(id="1234567890", body={})["status_code"] in AllowedResponses
        ) is True

    def test_entities_web_location_delete_v2(self):
        """Test delete web location endpoint"""
        assert bool(
            falcon.delete_web_location(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_entities_web_location_delete_v2_alias(self):
        """Test delete web location endpoint using PascalCase alias"""
        assert bool(
            falcon.DeleteWebLocationV2(ids="1234567890")["status_code"] in AllowedResponses
        ) is True

    def test_generate_errors(self):
        """Test error handling by forcing network failures"""
        # Save original base_url
        original_url = falcon.base_url
        # Set invalid URL to force errors
        falcon.base_url = "https://nowhere.invalid"
        
        error_checks = True
        tests = {
            "query_classifications": falcon.query_classifications(limit=1)["status_code"],
            "get_classification": falcon.get_classification(ids="test")["status_code"],
            "create_classification": falcon.create_classification(body={})["status_code"],
            "update_classification": falcon.update_classifications(body={})["status_code"],
            "delete_classification": falcon.delete_classification(ids="test")["status_code"],
            "query_cloud_apps": falcon.query_cloud_applications(limit=1)["status_code"],
            "get_cloud_app": falcon.get_cloud_application(ids="test")["status_code"],
            "create_cloud_app": falcon.create_cloud_application(body={})["status_code"],
            "query_content_patterns": falcon.query_content_patterns(limit=1)["status_code"],
            "get_content_pattern": falcon.get_content_pattern(ids="test")["status_code"],
            "query_policies": falcon.query_policies(platform_name="win", limit=1)["status_code"],
            "get_policies": falcon.get_policies(ids="test")["status_code"],
            "query_web_locations": falcon.query_web_locations(limit=1)["status_code"],
            "get_web_location": falcon.get_web_location(ids="test")["status_code"]
        }
        
        # Restore original URL
        falcon.base_url = original_url
        
        for key in tests:
            if tests[key] not in [400, 500]:
                error_checks = False
                # Uncomment for debugging
                # print(f"{key} test returned a {tests[key]} status code")
        
        assert error_checks is True

    @pytest.mark.skipif(config.base_url == "https://api.laggar.gcw.crowdstrike.com",
                        reason="Unit testing unavailable on US-GOV-1"
                        )
    def test_all_code_paths(self):
        """Comprehensive test of all main endpoints"""
        error_checks = True
        tests = {
            # Query endpoints
            "query_classifications_v2": falcon.query_classifications(limit=1),
            "query_cloud_applications_v2": falcon.query_cloud_applications(limit=1),
            "query_content_patterns_v2": falcon.query_content_patterns(limit=1),
            "query_enterprise_accounts_v2": falcon.query_enterprise_accounts(limit=1),
            "query_file_type_v2": falcon.query_file_type(limit=1),
            "query_sensitivity_label_v2": falcon.query_sensitivity_label(limit=1),
            "query_policies_v2": falcon.query_policies(platform_name="win", limit=1),
            "query_web_locations_v2": falcon.query_web_locations(limit=1),
            
            # Entity endpoints with test IDs
            "get_classification_v2": falcon.get_classification(ids="1234567890"),
            "get_cloud_application": falcon.get_cloud_application(ids="1234567890"),
            "get_content_pattern": falcon.get_content_pattern(ids="1234567890"),
            "get_enterprise_account": falcon.get_enterprise_account(ids="1234567890"),
            "get_file_type": falcon.get_file_type(ids="1234567890"),
            "get_sensitivity_label_v2": falcon.get_sensitivity_label(ids="1234567890"),
            "get_policies_v2": falcon.get_policies(ids="1234567890"),
            "get_web_location_v2": falcon.get_web_location(ids="1234567890"),
            
            # Create endpoints with minimal payloads
            "create_classification_v2": falcon.create_classification(body={}),
            "create_cloud_application": falcon.create_cloud_application(body={}),
            "create_content_pattern": falcon.create_content_pattern(body={}),
            "create_enterprise_account": falcon.create_enterprise_account(body={}),
            "create_sensitivity_label_v2": falcon.create_sensitivity_label(body={}),
            "create_policy_v2": falcon.create_policy(platform_name="win", body={}),
            "create_web_location_v2": falcon.create_web_location(body={}),
            
            # PascalCase alias tests
            "QueryClassificationsV2": falcon.QueryClassificationsV2(limit=1),
            "GetClassificationV2": falcon.GetClassificationV2(ids="1234567890"),
            "CreateClassificationV2": falcon.CreateClassificationV2(body={}),
            "QueryCloudApplicationsV2": falcon.QueryCloudApplicationsV2(limit=1),
            "GetCloudApplication": falcon.GetCloudApplication(ids="1234567890"),
            "CreateCloudApplication": falcon.CreateCloudApplication(body={}),
        }
        
        for key in tests:
            if tests[key]["status_code"] not in AllowedResponses:
                error_checks = False
                print(f"Failed test: {key}")
                print(f"Status code: {tests[key]['status_code']}")
        
        assert error_checks is True

    def test_missing_keyword_parameters(self):
        """Test error handling for missing required parameters"""
        # Test various methods with invalid arguments to ensure proper error handling
        assert bool(
            falcon.query_classifications("Invalid argument")["status_code"] == 500
        ) is True
        
        assert bool(
            falcon.get_classification("Invalid argument")["status_code"] == 500
        ) is True
        
        assert bool(
            falcon.create_classification("Invalid argument")["status_code"] == 500
        ) is True

r"""

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |                         |::.. . |           FalconPy
`-------'                         `-------'


This sample utilizes the Message Center service collection
to query, retrieve, and manage messages.

Creation date: 12.4.25 - alhumaw


The Message Center in the Falcon console lets you discuss detections,
ask questions, and receive info all from a single place.
With its filtering options and search capabilities,
Message Center helps you track old and new communication more effectively than email threads.
To present a full picture of your conversation with CrowdStrike,
Message Center also shows any emails you might send to the Falcon Complete or Falcon OverWatch Elite teams.


Accomplish these tasks using Message Center APIs:

    - Get the status and metadata of support cases for your awareness or records
    - View the messages and status changes of a support case as they happen
    - Upload a file attachment to an existing case
"""

import logging
import json
import csv
from argparse import ArgumentParser, RawTextHelpFormatter, Namespace
from datetime import datetime
try:
    from tabulate import tabulate  # type: ignore
except ImportError as no_tabulate:
    raise SystemExit("The tabulate library must be installed.\n"
                     "Install it with `python3 -m pip install tabulate`."
                     ) from no_tabulate
try:
    from falconpy import MessageCenter, APIError, UserManagement
except ImportError as no_falconpy:
    raise SystemExit("The CrowdStrike FalconPy library must be installed.\n"
                     "Install it with `python3 -m pip install crowdstrike-falconpy`."
                     ) from no_falconpy


def parse_command_line() -> Namespace:
    """Parse any provided command line arguments and return the namespace."""
    parser = ArgumentParser(description=__doc__,
                            formatter_class=RawTextHelpFormatter
                            )
    require = parser.add_argument_group("required arguments")
    require.add_argument("-k", "--client_id",
                         required=True,
                         help="CrowdStrike API client ID."
                         )
    require.add_argument("-s", "--client_secret",
                         required=True,
                         help="CrowdStrike API client secret."
                         )
    parser.add_argument("-d", "--debug",
                        help="Enable API debugging.",
                        action="store_true",
                        default=False
                        )

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument("-q", "--query",
                              help="Query and display cases.",
                              action="store_true",
                              default=False
                              )
    action_group.add_argument("-c", "--case",
                              help="Get details for a specific case ID.",
                              metavar="CASE_ID"
                              )

    parser.add_argument("--filter",
                        help="Filter using FQL syntax for the case query.",
                        default=None
                        )
    parser.add_argument("--upload",
                        help="File path to upload file to a specific case id.",
                        default=None
                        )
    parser.add_argument("--user_name",
                        help="User name of the user uploading the file (typically an email address).",
                        default=None
                        )
    parser.add_argument("--details",
                        help="Display message details.",
                        action="store_true",
                        default=False
                        )
    parser.add_argument("-o", "--output",
                        help="Output file path to export cases (for compliance/records).",
                        metavar="FILENAME",
                        default=None
                        )
    parser.add_argument("--format",
                        help="Export format (json or csv). Default: json",
                        choices=["json", "csv"],
                        default="json"
                        )

    parsed = parser.parse_args()

    if parsed.debug:
        logging.basicConfig(level=logging.DEBUG)

    if parsed.details and not parsed.case:
        parser.error("Must specify message to retrieve details.")

    if parsed.upload and not parsed.user_name:
        parser.error("Must specify user name (typically an email address).")

    return parsed

class MessageCenterManager:
    """Message Center API Interface."""
    def __init__(self, message_center: MessageCenter, user_management: UserManagement):
        self.message_center = message_center
        self.user_management = user_management

    def query_messages(self, filter: str = None) -> list:
        """Query messages.

        Parameters:
            filter -- Optional FQL filter expression to filter cases. String.
        
        Returns: list containing requested data from API.
        """

        response = self.message_center.query_cases(filter=filter, sort="case.created_time.desc")
        code = response.get('status_code', 500)
        if code == 200:
            case_ids = response['body']['resources']
            if not case_ids:
                print("No cases found matching the criteria.")
                return []
            return self.get_all_messages(case_ids=case_ids)
        else:
            print(f"Error querying cases. Status code: {code}")
            return []

    def get_all_messages(self, case_ids) -> None:
        """Grab all the messages.
       
        Parameters:
            case_ids -- The ids specified to filter upon.
        """
        response = self.message_center.get_cases(ids=case_ids)
        code = response.get('status_code', 500)
        if code == 200:
            all_cases = response['body']['resources']
            pretty_cases = []
            for case in all_cases:
                cur_case = []
                actual_title = None
                cur_id = case.get('id', None)
                cur_title = case.get('title', None)
                cur_time = case.get('created_time', None)
                if cur_title is not None:
                    actual_title = cur_title.split("|")[-1]

                cur_case.append(cur_id)
                cur_case.append(actual_title)
                cur_case.append(cur_time)

                pretty_cases.append(cur_case)

            table = tabulate(
                tabular_data=pretty_cases,
                headers=['ID', 'Title', 'Last Modified'],
                tablefmt='heavy_grid',
                maxcolwidths=30
            )
            print(table)
        else:
            print(f"Error. Status code: {code}")
            return

    def get_message(
            self,
            case_id: str,
            show_details: bool = False,
            file_upload_name: str = None,
            user_name: str = None
            ) -> None:
        """Get a specific case by ID.
        
        Parameters:
            case_id -- The case ID to retrieve. String.
            show_details -- Whether to show full message thread. Boolean.
        """

        if file_upload_name:
            return self._upload_file(case_id=case_id, file_name=file_upload_name, user_name=user_name)

        response = self.message_center.get_case_entities_by_ids(ids=case_id)
        code = response.get('status_code', 500)
        if code == 200:
            cases = response['body']['resources']
            if not cases:
                print(f"Case {case_id} not found.")
                return

            for case in cases:
                self._display_case_summary(case)

            if show_details:
                response = self.message_center.query_activity_by_case_id(case_id=case_id)
                code = response['status_code']
                if code != 200:
                    print(f"Error retrieving activity_ids. Status code {code}")
                activity_ids = response['body']['resources']
                response = self.message_center.get_case_activity_by_ids(ids=activity_ids)
                code = response['status_code']
                if code != 200:
                    print(f"Error retrieving activities. Status code {code}")
                activities = response['body']['resources']
                print("\n" + "="*80)
                print("CASE ACTIVITY")
                print("="*80)
                for activity in activities:
                    self._display_activity(activity)
        else:
            print(f"Error retrieving case. Status code: {code}")

    def _display_case_summary(self, case: dict):
        """Display summary information for a case.

        Parameters:
            cases -- The dictionary of cases. dict.
        """
        status = {
            "1": "Waiting for your response.",
            "2": "Waiting for review.",
            "3": "Closed. (resolved).",
            "4": "Closed. (unresolved)."

        }
        status_string = status.get(case.get('status', None), None)
        print(f"Case ID: {case.get('id', 'N/A')}")
        print(f"Title: {case.get('title', 'N/A').split('|')[-1].strip()}")
        print(f"Created: {case.get('created_time', 'N/A')}")
        print(f"Last Modified: {case.get('last_modified_time', 'N/A')}")
        print(f"Status: {status_string}")

    def _display_activity(self, activity: dict):
        """Display a single activity item with appropriate formatting based on type.
        
        Parameters:
            activity -- Activity dictionary from the API. Dict.
        """
        activity_type = activity.get('type', 'unknown')
        body = activity.get('body', '').strip()
        created_time = activity.get('created_time', 'N/A')
        created_by = activity.get('created_by', {})

        if not body or body.isdigit():
            return

        timestamp = f"[{created_time}]"

        if activity_type == 'status_change':
            print(f"\n{timestamp} STATUS: {body}")
        else:
            author = ""
            if created_by:
                display_name = created_by.get('display_name', '')
                first_name = created_by.get('first_name', '')
                last_name = created_by.get('last_name', '')

                if display_name:
                    author = f" ({display_name})"
                elif first_name or last_name:
                    author = f" ({first_name} {last_name})"

            print(f"\n{timestamp} MESSAGE{author}:")
            for line in body.split('\n'):
                print(f"    {line}")

    def export_cases(self, output_file: str, export_format: str = "json", filter: str = None) -> None:
        """Export all cases to a file for compliance/record keeping.
        
        Parameters:
            output_file -- Output file path. String.
            export_format -- Export format (json or csv). String.
            filter -- Optional FQL filter expression. String.
        """
        response = self.message_center.query_cases(filter=filter, sort="case.created_time.desc")
        code = response.get('status_code', 500)

        if code != 200:
            print(f"Error querying cases. Status code: {code}")
            return

        case_ids = response['body']['resources']
        if not case_ids:
            print("No cases found to export.")
            return

        response = self.message_center.get_cases(ids=case_ids)
        code = response.get('status_code', 500)

        if code != 200:
            print(f"Error retrieving case details. Status code: {code}")
            return

        cases = response['body']['resources']

        if export_format == "json":
            self._export_to_json(cases, output_file)
        elif export_format == "csv":
            self._export_to_csv(cases, output_file)

        print(f"Exported {len(cases)} cases to {output_file}")

    def _export_to_json(self, cases: list, output_file: str) -> None:
        """Export cases to JSON format.
        
        Parameters:
            cases -- A list of cases. list.
            output_file -- The name of the file to output to.
        """
        export_data = {
            "export_date": datetime.now().isoformat(),
            "total_cases": len(cases),
            "cases": cases
        }

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)

    def _export_to_csv(self, cases: list, output_file: str) -> None:
        """Export cases to CSV format.
        
        Parameters:
            cases -- A list of cases. list.
            output_file -- The name of the file to output to.
        """
        if not cases:
            return

        fieldnames = ['id', 'title', 'status', 'created_time', 'last_modified_time', 
                      'type', 'priority', 'body']

        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()

            for case in cases:
                if case.get('title'):
                    case['title'] = case['title'].split('|')[-1].strip()
                writer.writerow(case)

    def _upload_file(self, case_id: str, file_name: str, user_name: str) -> None:
        """Upload a file to a given case.

        Parameters:
            case_id -- The case ID. String.
            file_name -- The name of the file to upload. String.
        """

        try:
            with open(file_name, "rb") as f:
                file = f.read()
        except FileNotFoundError:
            print(f"File not found: {file_name}")
            return

        user_response = self.user_management.retrieve_user_uuid(user_name)
        code = user_response.get('status_code', 500)
        if code != 200:
            print(user_response)
            print(f"Error retrieving user uuid for user: {user_name}. Status code: {code}")
            return
        user_uuid = user_response['body']['resources']
        response = self.message_center.add_case_attachment(
            user_uuid=user_uuid,
            case_id=case_id,
            file_name=file_name,
            file_data=file
            )

        code = response.get('status_code', 500)
        if code == 200:
            print(f"Successfully uploaded {file_name} to case {case_id}")
        else:
            print(f"Error uploading file. Status code: {code}")


def message_center_handler(args: Namespace, message_center: MessageCenter, user_management: UserManagement) -> None:
    """Handle Message Center operations based on command line arguments.
    
    Parameters:
        args -- Parsed command line arguments. Namespace.
        falcon -- Authenticated MessageCenter instance.
    """
    message_manager = MessageCenterManager(message_center=message_center, user_management=user_management)

    if args.output:
        message_manager.export_cases(
            output_file=args.output,
            export_format=args.format,
            filter=args.filter
        )
    elif args.query:
        message_manager.query_messages(filter=args.filter)
    elif args.case:
        message_manager.get_message(
            case_id=args.case,
            show_details=args.details,
            file_upload_name=args.upload,
            user_name=args.user_name
            )
    else:
        message_manager.query_messages(filter=args.filter)

def connect_api(key: str, secret: str, debug: bool) -> MessageCenter:
    """Connect to the CrowdStrike API and return an MessageCenter instance.
    
    Parameters:
        key -- CrowdStrike API client ID. String.
        secret -- CrowdStrike API client secret. String.
        debug -- Enable debug logging. Boolean.
    
    Returns: MessageCenter service class instance.
    """
    try:
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        return (
            MessageCenter(client_id=key, client_secret=secret, debug=debug),
            UserManagement(client_id=key, client_secret=secret, debug=debug)
            )
    except APIError as e:
        print(f"Failed to connect to API: {e}")
        return e

def main():
    """Start Main Execution Routine."""
    args = parse_command_line()
    message_center, user_management = connect_api(
        key=args.client_id,
        secret=args.client_secret,
        debug=args.debug
        )

    message_center_handler(args=args, message_center=message_center, user_management=user_management)


if __name__ == "__main__":
    main()

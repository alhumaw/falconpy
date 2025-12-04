r"""

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |                         |::.. . |           FalconPy
`-------'                         `-------'


This sample utilizes the ScheduledReports service collection
to identify and execute reports.

Creation date: 12.4.25 - alhumaw
"""

import logging
from argparse import ArgumentParser, RawTextHelpFormatter, Namespace
try:
    from tabulate import tabulate  # type: ignore
except ImportError as no_tabulate:
    raise SystemExit("The tabulate library must be installed.\n"
                     "Install it with `python3 -m pip install tabulate`."
                     ) from no_tabulate
try:
    from falconpy import ScheduledReports, APIError
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
    exclusive_group = parser.add_mutually_exclusive_group()
    exclusive_group.add_argument("-e", "--execute",
                                 help="The scheduled report ID to execute.",
                                 )
    exclusive_group.add_argument("-q", "--query",
                                 help="Locate scheduled report(s).",
                                 action="store_true",
                                 default=False
                                 )
    parser.add_argument("-n", "--name",
                        help="Search for reports by username or report name (case-insensitive partial match).",
                        default=None
                        )
    parsed = parser.parse_args()

    if parsed.debug:
        logging.basicConfig(level=logging.DEBUG)

    return parsed


class Reports:
    """Scheduled Reports API Interface."""
    def __init__(self, falcon: ScheduledReports):
        self.falcon = falcon

    def start_report(self, report_id: str):
        """Launch a scheduled report execution.
        
        Parameters:
            report_id -- The ID of the scheduled report to execute. String.
        
        Returns: None. Prints execution status.
        """
        response = self.falcon.launch(id=report_id)
        code = response.get('status_code', 500)
        if code == 200:
            execution_id = response
            print(f"Successfully Executed Scheduled Report {report_id}")
        else:
            error_msg = response['body'].get('errors', [{}])[0].get('message', 'Unknown error')
            print(f"Error launching report. Status code: {code}")
            print(f"Error message: {error_msg}")

    def _get_reports(self, report_ids: list, search_name: str = None) -> list:
        """Locate the scheduled reports from given report_ids.
        
        Parameters:
            report_ids -- The IDs of the reports to grab. list.
            search_name -- Optional search term to filter by username or report name. String.
        
        Returns: list containing requested data from API.
        """
        all_reports = []
        response = self.falcon.get_reports(ids=report_ids)
        code = response.get('status_code', 500)
        if code == 200:
            grab_report = response['body']['resources']
        else:
            print(f"Error. Status code: {code}")
            return []
        
        if grab_report:
            print(f"Found {len(grab_report)} report(s)")
        
        for report in grab_report:
            cur_id = report.get('id', None)
            cur_name = report.get('name', None)
            last_executed_dict = report.get('last_execution', {})
            last_executed = last_executed_dict.get('last_updated_on', None)
            
            user_id = report.get('user_id', '')
            
            if search_name:
                search_lower = search_name.lower()
                name_match = cur_name and search_lower in cur_name.lower()
                user_match = user_id and search_lower in user_id.lower()
                
                if not (name_match or user_match):
                    continue
            
            list_report = [cur_id, cur_name, user_id, last_executed]
            all_reports.append(list_report)
        
        return all_reports

    def find_reports(self, filter: str = None, search_name: str = None) -> list:
        """Query all scheduled reports.

        Parameters:
            search_name -- Optional search term to filter by username or report name. String.
        
        Returns: list containing requested data from API.
        """
        response = self.falcon.query_reports(limit=10000000)
        code = response.get('status_code', 500)
        if code == 200:
            report_ids = response['body']['resources']
            return self._get_reports(report_ids, search_name=search_name)
        else:
            print(f"Error. Status code: {code}")
            return []

def pretty_print_reports(all_reports: list) -> None:
    """Display reports in a formatted table.
    
    Parameters:
        all_reports -- List of report data. List.
    """
    if not all_reports:
        print("No reports found matching the criteria.")
        return
    
    table = tabulate(
        all_reports,
        headers=['ID', 'Name', 'Created By', 'Last Executed Date'],
        tablefmt='grid'
    )

    print(table)

def report_handler(args: Namespace, falcon: ScheduledReports) -> None:
    """Interface with the ScheduledReports API. Execute instructions and gather results.
    
    Parameters:
        args - The arguments parsed from user input. Namespace.
        falcon - The ScheduledReports uber class. ScheduledReports.
    """
    report = Reports(falcon)

    if args.query:
        all_reports = report.find_reports(search_name=args.name)
        pretty_print_reports(all_reports)
    elif args.execute:
        report.start_report(report_id=args.execute)

def connect_api(key: str, secret: str, debug: bool) -> ScheduledReports:
    """Connect to the CrowdStrike API and return a ScheduledReports instance.
    
    Parameters:
        key -- CrowdStrike API client ID. String.
        secret -- CrowdStrike API client secret. String.
        debug -- Enable debug logging. Boolean.
    
    Returns: ScheduledReports uber class instance.
    """
    try:
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        return ScheduledReports(client_id=key, client_secret=secret, debug=debug)
    except APIError as e:
        print(f"Failed to connect to API: {e}")
        return e

def main():
    """Start Main Execution Routine."""
    args = parse_command_line()
    falcon = connect_api(key=args.client_id, secret=args.client_secret, debug=args.debug)
    report_handler(args, falcon)


if __name__ == "__main__":
    main()

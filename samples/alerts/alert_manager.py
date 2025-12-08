r"""
 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |                         |::.. . |           FalconPy
`-------'                         `-------'

This sample utilizes the Alerts service collection
to query, retrieve, and manage security alerts.

USAGE EXAMPLES:
    # List alerts with filter
    python alert_manager.py -k $KEY -s $SECRET --list --filter "product:'automated-lead'"
    
    # View specific alert details
    python alert_manager.py -k $KEY -s $SECRET --view <composite_id>
    
    # Update alert status
    python alert_manager.py -k $KEY -s $SECRET --update <composite_id> --status closed
    
    # Export to JSON
    python alert_manager.py -k $KEY -s $SECRET --list --filter "severity:'High'" --export

Creation date: 12.4.25 - alhumaw
"""

import json
import logging
from datetime import datetime
from argparse import ArgumentParser, RawTextHelpFormatter, Namespace
try:
    from tabulate import tabulate
except ImportError as no_tabulate:
    raise SystemExit("The tabulate library must be installed.\n"
                     "Install it with `python3 -m pip install tabulate`."
                     ) from no_tabulate
try:
    from falconpy import Alerts, APIError
except ImportError as no_falconpy:
    raise SystemExit("The CrowdStrike FalconPy library must be installed.\n"
                     "Install it with `python3 -m pip install crowdstrike-falconpy`."
                     ) from no_falconpy


def parse_command_line() -> Namespace:
    """Parse any provided command line arguments and return the namespace."""
    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    
    require = parser.add_argument_group("required arguments")
    require.add_argument("-k", "--client_id", required=True, help="CrowdStrike API client ID")
    require.add_argument("-s", "--client_secret", required=True, help="CrowdStrike API client secret")
    
    parser.add_argument("-d", "--debug", help="Enable API debugging", action="store_true", default=False)
    
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("-l", "--list", help="List alerts", action="store_true")
    action_group.add_argument("-v", "--view", help="View specific alert by composite ID", metavar="COMPOSITE_ID")
    action_group.add_argument("-u", "--update", help="Update alert by composite ID", metavar="COMPOSITE_ID")
    
    parser.add_argument("-f", "--filter", help="FQL filter string", default=None)
    parser.add_argument("--status", 
                       help="New status when updating:\n"
                            "  Strings: new, in_progress, reopened, closed, ignored\n"
                            "  Numbers: 20 (new), 25 (reopened), 30 (in_progress), 40 (closed)")
    parser.add_argument("-e", "--export", help="Export results to JSON file", action="store_true")
    parser.add_argument("--limit", help="Maximum number of alerts to return (default: 100)", type=int, default=100)
    
    parsed = parser.parse_args()
    
    if parsed.debug:
        logging.basicConfig(level=logging.DEBUG)
    
    if parsed.update and not parsed.status:
        parser.error("--update requires --status")
    
    return parsed


class AlertManager:
    """Manage CrowdStrike alerts."""
    
    STATUS_MAP = {
        '20': 'new',
        '25': 'reopened',
        '30': 'in_progress',
        '40': 'closed',
        'new': '20',
        'reopened': '25',
        'in_progress': '30',
        'closed': '40',
        'ignored': 'ignored'
    }
    
    def __init__(self, falcon: Alerts):
        self.falcon = falcon
    
    def _normalize_status(self, status: str) -> str:
        """Normalize status to the format expected by the API.
        
        Parameters:
            status -- The status to normalize.
        
        Returns: A normalized status (new -> 20)
        """
        return self.STATUS_MAP.get(status.lower(), status)
    
    def list_alerts(self, filter_str: str = None, limit: int = 100, export: bool = False) -> None:
        """List alerts with optional filter.
        
        Parameters:
            filter_str -- The FQL syntax filter to utilize.
            limit -- The amount of results to output.
            export -- If set, output to json.
        """
        print(f"Querying alerts{' with filter: ' + filter_str if filter_str else ''}...")
        
        response = self.falcon.query_alerts_v2(filter=filter_str, limit=limit)
        if response.get('status_code') != 200:
            print(f"Error querying alerts: {response.get('status_code')}")
            if response.get('body', {}).get('errors'):
                print(f"Details: {response['body']['errors']}")
            return
        
        alert_ids = response.get('body', {}).get('resources', [])
        if not alert_ids:
            print("No alerts found.")
            return
        
        pagination = response.get('body', {}).get('meta', {}).get('pagination', {})
        total = pagination.get('total', 0)
        if total > limit:
            print(f"Showing {len(alert_ids)} of {total} total alerts.\n")
        
        details_response = self.falcon.get_alerts_v2(composite_ids=alert_ids)
        if details_response.get('status_code') != 200:
            print("Error fetching alert details.")
            return
        
        alerts = details_response.get('body', {}).get('resources', [])
        
        if export:
            self._export_alerts(alerts)
        else:
            self._display_alerts(alerts)
    
    def view_alert(self, composite_id: str) -> None:
        """View detailed information for a specific alert.
        
        Parameters:
            composite_id -- The alert id to view.
        """
        print(f"Fetching alert details for: {composite_id}\n")
        
        response = self.falcon.get_alerts_v2(composite_ids=[composite_id])
        if response.get('status_code') != 200:
            print(f"Error fetching alert: {response.get('status_code')}")
            return
        
        alerts = response.get('body', {}).get('resources', [])
        if not alerts:
            print("Alert not found.")
            return
        
        self._display_alert_detail(alerts[0])
    
    def update_alert(self, composite_id: str, status: str) -> None:
        """Update alert status.
        
        Parameters:
            composite_id -- The id of the alert to update.
            status -- The status to update the alert to.
        """
        normalized_status = self._normalize_status(status)
        print(f"Updating alert {composite_id} to status: {normalized_status} (from: {status})")
        
        response = self.falcon.update_alerts_v3(
            composite_ids=[composite_id],
            update_status=normalized_status
        )
        
        if response.get('status_code') == 200:
            print(f"✓ Alert updated successfully to '{normalized_status}'")
        else:
            print(f"Error updating alert: {response.get('status_code')}")
            if response.get('body', {}).get('errors'):
                print(f"Details: {response['body']['errors']}")
    
    def _display_alerts(self, alerts: list) -> None:
        """Display alerts in a table.
        
        Parameters:
            alerts -- The alerts list.
        """
        if not alerts:
            return
        
        table_data = []
        for alert in alerts:
            # Truncate long IDs for display
            alert_id = alert.get('composite_id', 'N/A')
            short_id = alert_id.split(':')[-1][:16] + '...' if ':' in alert_id else alert_id[:16]
            
            table_data.append([
                alert_id,
                alert.get('created_timestamp', 'N/A')[:19],
                alert.get('severity_name', 'N/A'),
                alert.get('status', 'N/A'),
                alert.get('product', 'N/A'),
                alert.get('name', 'N/A')[:50]
            ])
        
        headers = ['Alert ID', 'Created', 'Severity', 'Status', 'Product', 'Name']
        print(tabulate(table_data, headers=headers, tablefmt='simple'))
        print(f"\nTotal: {len(alerts)} alerts")
        print("\nUse --view <composite_id> to see full details (copy from export or API)")
    
    def _display_alert_detail(self, alert: dict) -> None:
        """Display detailed information for a single alert.
        
        Parameters:
            alert -- The dictionary of alerts.
        """
        print("=" * 70)
        print(f"Alert ID:    {alert.get('composite_id', 'N/A')}")
        print(f"Status:      {alert.get('status', 'N/A')}")
        print(f"Severity:    {alert.get('severity_name', 'N/A')}")
        print(f"Product:     {alert.get('product', 'N/A')}")
        print(f"Created:     {alert.get('created_timestamp', 'N/A')}")
        print(f"Updated:     {alert.get('updated_timestamp', 'N/A')}")
        
        if alert.get('name'):
            print(f"\nName:        {alert['name']}")
        
        if alert.get('description'):
            print(f"\nDescription:\n{alert['description']}")
        
        if alert.get('tactic'):
            print(f"\nTactic:      {alert['tactic']}")
        if alert.get('technique'):
            print(f"Technique:   {alert['technique']}")
        
        if alert.get('assigned_to_name'):
            print(f"\nAssigned to: {alert['assigned_to_name']}")
        
        print("=" * 70)
    
    def _export_alerts(self, alerts: list) -> None:
        """Export alerts to JSON file.
        
        Parameters:
            alerts -- The alerts to export.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"alerts_export_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(alerts, f, indent=2)
        
        print(f"✓ Exported {len(alerts)} alerts to {filename}")


def connect_api(key: str, secret: str, debug: bool) -> Alerts:
    """Connect to the CrowdStrike API.
    
    Parameters:
        key -- CrowdStrike API client ID. String.
        secret -- CrowdStrike API client secret. String.
        debug -- Enable debug logging. Boolean.
    
    Returns: Alerts service class instance.
    """
    try:
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        return Alerts(client_id=key, client_secret=secret, debug=debug)
    except APIError as e:
        raise SystemExit(f"Failed to connect to API: {e}") from e


def main():
    """Main execution routine."""
    args = parse_command_line()
    falcon = connect_api(key=args.client_id, secret=args.client_secret, debug=args.debug)
    
    manager = AlertManager(falcon=falcon)
    
    if args.list:
        manager.list_alerts(filter_str=args.filter, limit=args.limit, export=args.export)
    elif args.view:
        manager.view_alert(composite_id=args.view)
    elif args.update:
        manager.update_alert(composite_id=args.update, status=args.status)


if __name__ == "__main__":
    main()

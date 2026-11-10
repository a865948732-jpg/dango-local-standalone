"""Payment result categories shared by filtering and batch statistics."""
from decimal import Decimal, InvalidOperation
from typing import Any


def explicit_zero(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return False
    if isinstance(value, str) and not value.strip():
        return False
    try:
        amount = Decimal(str(value))
        return amount.is_finite() and amount == 0
    except InvalidOperation:
        return False


def qualification_category(row: Any) -> str:
    """Match the UI's qualificationCategory, including legacy regional fallback."""
    if not isinstance(row, dict) or row.get('status') == 'queued':
        return 'pending'
    if row.get('status') in {'failed', 'interrupted', 'cancelled', 'error'}:
        return 'failed'
    if row.get('status') in {'checking', 'running'} and not row.get('error'):
        return 'checking'
    if row.get('error') or row.get('interrupted'):
        return 'failed'
    regions = row.get('regions')
    for region in regions if isinstance(regions, list) else []:
        if not isinstance(region, dict):
            continue
        methods = region.get('payment_method_types')
        amount = region.get('amount_minor')
        if row.get('routing_version') != 2:
            if methods is None:
                methods = row.get('payment_method_types') or row.get('available_channels') or []
            if amount is None:
                amount = row.get('amount_minor')
        channel = str(region.get('channel') or '').lower()
        if (region.get('qualified') is True and channel and not region.get('error')
                and not region.get('reason_codes') and isinstance(methods, list)
                and channel in [str(method).lower() for method in methods]
                and explicit_zero(amount)
                and (not region.get('requested_country') or region.get('country') == region['requested_country'])
                and (not region.get('requested_currency') or region.get('currency') == region['requested_currency'])):
            return 'eligible'
    return 'ineligible'

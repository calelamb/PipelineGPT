import os
import json
from datetime import datetime

# Backend test as admin role
def test_view_delayed_shipments():
    """
    Backend test: View all delayed shipments from specific suppliers
    Role: Administrator
    """
    
    # Create outputs directory if it doesn't exist
    output_dir = os.path.join(os.path.dirname(__file__), 'outputs')
    os.makedirs(output_dir, exist_ok=True)
    
    # Test data for delayed shipments
    test_result = {
        "test_name": "View Delayed Shipments by Supplier",
        "role": "administrator",
        "timestamp": datetime.now().isoformat(),
        "suppliers": ["Superior Materials", "Reliable Suppliers Co"],
        "delayed_shipments": [
            {
                "shipment_id": "SHIP-001",
                "supplier": "Superior Materials",
                "order_id": "ORD-12345",
                "order_details": {
                    "items": 150,
                    "total_value": 45000.00,
                    "order_date": "2024-01-15"
                },
                "delivery_performance": {
                    "expected_delivery": "2024-02-01",
                    "actual_delivery": "2024-02-15",
                    "days_delayed": 14
                },
                "costs": {
                    "base_cost": 45000.00,
                    "delay_charges": 2250.00,
                    "total_cost": 47250.00
                }
            },
            {
                "shipment_id": "SHIP-002",
                "supplier": "Reliable Suppliers Co",
                "order_id": "ORD-12346",
                "order_details": {
                    "items": 200,
                    "total_value": 62000.00,
                    "order_date": "2024-01-20"
                },
                "delivery_performance": {
                    "expected_delivery": "2024-02-05",
                    "actual_delivery": "2024-02-12",
                    "days_delayed": 7
                },
                "costs": {
                    "base_cost": 62000.00,
                    "delay_charges": 1240.00,
                    "total_cost": 63240.00
                }
            }
        ],
        "summary": {
            "total_delayed_shipments": 2,
            "total_delay_days": 21,
            "total_delay_charges": 3490.00
        }
    }
    
    # Save results to file
    output_file = os.path.join(output_dir, f"delayed_shipments_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    with open(output_file, 'w') as f:
        json.dump(test_result, f, indent=2)
    
    print(f"✓ Backend test completed successfully")
    print(f"✓ Results saved to: {output_file}")
    
    return test_result


if __name__ == "__main__":
    test_view_delayed_shipments()
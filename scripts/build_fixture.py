from pathlib import Path

from white_hat_agent.fixtures import write_active_data_fixture, write_stalled_recovery_fixture

if __name__ == "__main__":
    fixture_paths = [
        *write_active_data_fixture(Path("fixtures")),
        *write_stalled_recovery_fixture(Path("fixtures")),
    ]
    for fixture_path in fixture_paths:
        print(fixture_path)

from pathlib import Path

from white_hat_agent.schemas import export_schemas

if __name__ == "__main__":
    for schema_path in export_schemas(Path("schemas")):
        print(schema_path)

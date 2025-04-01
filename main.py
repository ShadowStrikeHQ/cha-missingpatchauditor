import argparse
import json
import logging
import os
import sys
from typing import Dict, List, Tuple, Union

import jsonschema
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Define schemas for YAML/JSON validation
BASELINE_SCHEMA = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "software": {"type": "string"},
                    "installed_version": {"type": "string"},
                    "required_version": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": [
                    "name",
                    "software",
                    "installed_version",
                    "required_version",
                    "severity",
                ],
            },
        },
    },
    "required": ["description", "rules"],
}

VULNERABILITIES_DB_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "software": {"type": "string"},
            "version": {"type": "string"},
            "cve": {"type": "string"},
            "description": {"type": "string"},
        },
        "required": ["software", "version", "cve", "description"],
    },
}


def setup_argparse() -> argparse.ArgumentParser:
    """Sets up the argument parser for the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Compares installed software versions against a vulnerabilities database and reports missing patches."
    )
    parser.add_argument(
        "-b",
        "--baseline",
        type=str,
        required=True,
        help="Path to the baseline YAML or JSON file.",
    )
    parser.add_argument(
        "-d",
        "--database",
        type=str,
        required=True,
        help="Path to the vulnerabilities database JSON file.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Path to the output file (optional). If not specified, output will be printed to stdout.",
    )
    return parser


def load_data(file_path: str) -> Union[Dict, List]:
    """Loads data from a YAML or JSON file.

    Args:
        file_path: The path to the file.

    Returns:
        A dictionary or list representing the data in the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file format is invalid (not YAML or JSON).
    """
    try:
        with open(file_path, "r") as f:
            if file_path.endswith((".yaml", ".yml")):
                return yaml.safe_load(f)
            elif file_path.endswith(".json"):
                return json.load(f)
            else:
                raise ValueError("Unsupported file format. Use YAML or JSON.")
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON file: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def validate_data(data: Union[Dict, List], schema: Dict) -> None:
    """Validates data against a JSON schema.

    Args:
        data: The data to validate.
        schema: The JSON schema to validate against.

    Raises:
        jsonschema.exceptions.ValidationError: If the data does not conform to the schema.
    """
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.exceptions.ValidationError as e:
        logging.error(f"Validation error: {e}")
        raise


def check_missing_patches(
    baseline_data: Dict, vulnerabilities_db: List[Dict]
) -> List[Dict]:
    """Checks for missing security patches based on the baseline and vulnerabilities database.

    Args:
        baseline_data: A dictionary containing the baseline configuration.
        vulnerabilities_db: A list of dictionaries representing the vulnerabilities database.

    Returns:
        A list of dictionaries, where each dictionary represents a missing patch.
    """
    missing_patches = []
    for rule in baseline_data["rules"]:
        software = rule["software"]
        installed_version = rule["installed_version"]
        required_version = rule["required_version"]

        # Check if the installed version is less than the required version
        if installed_version < required_version:
            # Search for vulnerabilities related to this software and version
            for vulnerability in vulnerabilities_db:
                if (
                    vulnerability["software"] == software
                    and vulnerability["version"] == installed_version
                ):
                    missing_patches.append(
                        {
                            "name": rule["name"],
                            "software": software,
                            "installed_version": installed_version,
                            "required_version": required_version,
                            "cve": vulnerability["cve"],
                            "description": vulnerability["description"],
                            "severity": rule["severity"],
                        }
                    )
    return missing_patches


def output_results(results: List[Dict], output_file: str = None) -> None:
    """Outputs the results to the console or a file.

    Args:
        results: A list of dictionaries containing the results.
        output_file: The path to the output file (optional).
    """
    if output_file:
        try:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4)
            logging.info(f"Results written to: {output_file}")
        except Exception as e:
            logging.error(f"Error writing to file: {e}")
            sys.exit(1)
    else:
        if results:
            print(json.dumps(results, indent=4))
        else:
            print("No missing patches found.")


def main() -> None:
    """Main function to execute the missing patch auditor."""
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        # Load and validate baseline data
        baseline_data = load_data(args.baseline)
        validate_data(baseline_data, BASELINE_SCHEMA)

        # Load and validate vulnerabilities database
        vulnerabilities_db = load_data(args.database)
        validate_data(vulnerabilities_db, VULNERABILITIES_DB_SCHEMA)

        # Check for missing patches
        missing_patches = check_missing_patches(baseline_data, vulnerabilities_db)

        # Output results
        output_results(missing_patches, args.output)

    except FileNotFoundError:
        sys.exit(1)
    except ValueError:
        sys.exit(1)
    except jsonschema.exceptions.ValidationError:
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
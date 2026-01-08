"""CLI entry point for STIG Generator."""

import sys
from datetime import datetime
from pathlib import Path

import typer

from .classifiers.automatable import classify_controls
from .generators.ansible_checker import generate_checker_playbook
from .generators.ansible_hardening import generate_hardening_playbook
from .generators.ctp_doc import generate_ctp_document
from .parsers.xccdf_parser import parse_xccdf

app = typer.Typer(help="STIG Generator - Generate Ansible playbooks and CTP documents from DISA STIG XCCDF files")


@app.command()
def generate(
    stig_file: Path = typer.Option(..., "--stig-file", "-f", help="Path to XCCDF XML STIG file"),
    product: str = typer.Option("rhel8", "--product", "-p", help="Product identifier (e.g., rhel8)"),
    output_dir: Path = typer.Option(
        Path("output"), "--output-dir", "-o", help="Output directory for generated artifacts"
    ),
    check_type: str = typer.Option(
        "both", "--check-type", "-c", 
        help="Type of checks for checker playbook: 'automated', 'manual', or 'both' (default: both)"
    ),
) -> None:
    """
    Generate Ansible playbooks and CTP document from a STIG XCCDF XML file.

    Example:
        python -m app.main --stig-file stigs/input/RHEL_8_STIG.xml --product rhel8
    """
    # Validate input file
    if not stig_file.exists():
        typer.echo(f"Error: STIG file not found: {stig_file}", err=True)
        sys.exit(1)

    # Validate check_type early
    if check_type not in ["automated", "manual", "both"]:
        typer.echo(f"Error: check_type must be 'automated', 'manual', or 'both', got: {check_type}", err=True)
        sys.exit(1)
    
    typer.echo(f"Parsing STIG file: {stig_file}")
    typer.echo(f"Product: {product}")

    try:
        # Parse XCCDF - OS family will be extracted from STIG
        controls = parse_xccdf(stig_file, os_family=None)
        
        if not controls:
            typer.echo("Warning: No controls found in STIG file. Generated files will be empty.", err=True)
        
        # Get OS family from first control (all controls have same os_family)
        if controls:
            os_family = controls[0].os_family
            typer.echo(f"Detected OS Family: {os_family}")
        else:
            os_family = "rhel"  # Default fallback
            typer.echo(f"Warning: Could not detect OS family, defaulting to: {os_family}", err=True)
        
        typer.echo(f"Parsed {len(controls)} STIG controls")

        # Classify controls
        typer.echo("Classifying controls...")
        controls = classify_controls(controls)
        automatable_count = sum(1 for c in controls if c.is_automatable)
        manual_count = len(controls) - automatable_count
        typer.echo(f"  - Automatable: {automatable_count}")
        typer.echo(f"  - Manual: {manual_count}")

        # Build metadata
        stig_metadata = {
            "stig_name": stig_file.stem,
            "stig_release": "Unknown",  # Could be extracted from XML if available
            "source_file_name": stig_file.name,
            "generated_on": datetime.now().isoformat(),
        }

        # Generate outputs
        output_dir = Path(output_dir)
        ansible_dir = output_dir / "ansible"
        ctp_dir = output_dir / "ctp"

        # Hardening playbook
        hardening_path = ansible_dir / f"stig_{product}_hardening.yml"
        typer.echo(f"\nGenerating hardening playbook: {hardening_path}")
        try:
            generate_hardening_playbook(controls, hardening_path, stig_metadata)
        except Exception as e:
            typer.echo(f"Error generating hardening playbook: {e}", err=True)
            raise
        
        # Checker playbook
        checker_path = ansible_dir / f"stig_{product}_checker.yml"
        typer.echo(f"Generating checker playbook: {checker_path} (check_type: {check_type})")
        try:
            generate_checker_playbook(controls, checker_path, stig_metadata, check_type=check_type)
        except Exception as e:
            typer.echo(f"Error generating checker playbook: {e}", err=True)
            raise

        # CTP document
        ctp_path = ctp_dir / f"stig_{product}_ctp.csv"
        typer.echo(f"Generating CTP document: {ctp_path}")
        try:
            generate_ctp_document(controls, ctp_path, stig_metadata)
        except Exception as e:
            typer.echo(f"Error generating CTP document: {e}", err=True)
            raise

        typer.echo("\n✓ Generation complete!")
        typer.echo(f"\nGenerated files:")
        typer.echo(f"  - {hardening_path}")
        typer.echo(f"  - {checker_path}")
        typer.echo(f"  - {ctp_path}")

    except FileNotFoundError as e:
        typer.echo(f"Error: File not found: {e}", err=True)
        sys.exit(1)
    except ValueError as e:
        typer.echo(f"Error: Invalid input: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        import traceback
        typer.echo(traceback.format_exc(), err=True)
        sys.exit(1)


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()


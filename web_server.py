"""Flask web server for STIG Generator GUI.

Provides a web interface for uploading STIG files and generating artifacts.
"""

import json
import logging
import sys
from functools import lru_cache
from pathlib import Path
from tempfile import NamedTemporaryFile

from flask import Flask, jsonify, render_template, request, send_file

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent))

from scripts.generate_checker import generate_checker_playbook
from scripts.generate_ctp import generate_ctp_csv
from scripts.generate_hardening import generate_hardening_playbook
from scripts.parse_stig import parse_xccdf_file, save_controls_to_json

# Configure logging
# Try to create file handler, but fall back to stream-only if it fails
# (e.g., in Railway or other restricted environments)
try:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
        handlers=[
            logging.FileHandler("server.log"),
            logging.StreamHandler()
        ]
    )
except (PermissionError, OSError):
    # Fall back to stream-only logging if file logging fails
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
        handlers=[logging.StreamHandler()]
    )
logger = logging.getLogger(__name__)

# Use absolute paths based on script location
BASE_DIR = Path(__file__).parent.resolve()

# Initialize Flask app with explicit template folder
app = Flask(__name__, template_folder=str(BASE_DIR / 'templates'))
app.config['UPLOAD_FOLDER'] = BASE_DIR / 'stigs' / 'input'
app.config['OUTPUT_FOLDER'] = BASE_DIR / 'output'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Ensure directories exist (with error handling for Railway)
try:
    app.config['UPLOAD_FOLDER'].mkdir(parents=True, exist_ok=True)
    app.config['OUTPUT_FOLDER'].mkdir(parents=True, exist_ok=True)
    (app.config['OUTPUT_FOLDER'] / 'ansible').mkdir(parents=True, exist_ok=True)
    (app.config['OUTPUT_FOLDER'] / 'ctp').mkdir(parents=True, exist_ok=True)
except Exception as e:
    logger.warning(f"Could not create directories: {e}")
    # Continue anyway - directories might already exist or be created on first use


def _auto_detect_benchmark2(stig_path: Path, original_filename: str = None) -> tuple[Path | None, str]:
    """Auto-detect benchmark2 file based on STIG file name.
    
    Args:
        stig_path: Path to the STIG file (may be temporary)
        original_filename: Original filename from upload (used for matching)
    
    Returns:
        Tuple of (benchmark_path, artifact_type) or (None, '') if not found
    """
    # Use original filename if provided, otherwise use path name
    stig_name = original_filename if original_filename else stig_path.name
    
    # Extract product identifier
    if 'RHEL_9' in stig_name or 'rhel9' in stig_name.lower():
        product = 'RHEL_9'
    elif 'RHEL_8' in stig_name or 'rhel8' in stig_name.lower():
        product = 'RHEL_8'
    elif 'Windows_11' in stig_name:
        product = 'MS_Windows_11'
    elif 'Windows_Server_2022' in stig_name:
        product = 'MS_Windows_Server_2022'
    else:
        return None, ''
    
    # Look for benchmark2 file
    benchmark2_dir = BASE_DIR / 'stigs' / 'benchmark2'
    if not benchmark2_dir.exists():
        return None, ''
    
    # Try to find matching benchmark file
    pattern = f"U_{product}*SCAP*Benchmark*.xml"
    matches = list(benchmark2_dir.glob(pattern))
    
    if matches:
        logger.info(f"Auto-detected benchmark2 file: {matches[0]}")
        return matches[0], 'scap'
    
    return None, ''


@app.route('/')
def index():
    """Serve the main page."""
    return render_template('index.html')


@app.route('/api/generate', methods=['POST'])
def generate():
    """Generate STIG artifacts from uploaded file."""
    try:
        if 'stig_file' not in request.files:
            return jsonify({'error': 'No STIG file provided'}), 400
        
        stig_file = request.files['stig_file']
        if stig_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save uploaded file temporarily
        with NamedTemporaryFile(delete=False, suffix='.xml', dir=app.config['UPLOAD_FOLDER']) as tmp_file:
            stig_file.save(tmp_file.name)
            stig_path = Path(tmp_file.name)
        
        # Handle secondary artifact (SCAP benchmark or Nessus scan)
        secondary_artifact = None
        secondary_type = request.form.get('secondary_type', '').strip()
        
        if 'secondary_artifact' in request.files:
            sec_file = request.files['secondary_artifact']
            if sec_file.filename:
                with NamedTemporaryFile(delete=False, suffix='.xml') as tmp_sec:
                    sec_file.save(tmp_sec.name)
                    secondary_artifact = Path(tmp_sec.name)
                    if not secondary_type:
                        # Auto-detect type
                        secondary_type = 'scap' if 'SCAP' in sec_file.filename or 'Benchmark' in sec_file.filename else 'nessus'
        
        # Auto-detect benchmark2 if no secondary artifact provided
        # Use original filename for matching, not the temporary file path
        if not secondary_artifact:
            benchmark_path, artifact_type = _auto_detect_benchmark2(stig_path, original_filename=stig_file.filename)
            if benchmark_path:
                secondary_artifact = benchmark_path
                secondary_type = artifact_type
        
        # Parse STIG file
        logger.info(f"Parsing XCCDF file: {stig_path}")
        
        # Create temporary JSON output
        with NamedTemporaryFile(delete=False, suffix='.json', mode='w') as tmp_json:
            json_path = Path(tmp_json.name)
        
        # Parse with secondary artifact if available
        # Pass original filename for better product detection
        if secondary_artifact:
            logger.info(f"Using secondary artifact: {secondary_artifact} (type: {secondary_type})")
            controls = parse_xccdf_file(
                stig_path,
                secondary_artifact=secondary_artifact,
                secondary_type=secondary_type,
                original_filename=stig_file.filename
            )
        else:
            controls = parse_xccdf_file(stig_path, original_filename=stig_file.filename)
        
        # Save to JSON
        save_controls_to_json(controls, json_path)
        
        # Convert to dict format for generators
        controls_dict = [c.to_dict() if hasattr(c, 'to_dict') else c for c in controls]
        
        # Extract product from controls, or try to detect from original filename
        product = controls_dict[0].get('product', 'unknown') if controls_dict else 'unknown'
        
        # Normalize product tag (handle variations)
        if product and product != 'unknown':
            # Normalize common variations
            product_lower = product.lower()
            if 'rhel' in product_lower or 'redhat' in product_lower:
                if '9' in product_lower or 'nine' in product_lower:
                    product = 'rhel9'
                elif '8' in product_lower or 'eight' in product_lower:
                    product = 'rhel8'
                elif '7' in product_lower:
                    product = 'rhel7'
                else:
                    product = 'rhel9'  # Default to latest
            elif 'windows' in product_lower:
                if '2022' in product_lower or 'server_2022' in product_lower:
                    product = 'windows2022'
                elif '2019' in product_lower or 'server_2019' in product_lower:
                    product = 'windows2019'
                elif '11' in product_lower:
                    product = 'windows11'
                elif '10' in product_lower:
                    product = 'windows10'
                else:
                    product = 'windows2022'  # Default to latest
            elif 'cisco' in product_lower:
                if 'ios' in product_lower and 'router' in product_lower:
                    product = 'cisco_ios_router'
                elif 'ios' in product_lower and 'switch' in product_lower:
                    product = 'cisco_ios_switch'
                elif 'nx-os' in product_lower:
                    product = 'cisco_nxos_switch'
                elif 'ise' in product_lower:
                    product = 'cisco_ise'
                else:
                    product = 'cisco_ios_router'  # Default
        
        # If product is still "unknown", try to detect from original filename
        if product == 'unknown' and stig_file.filename:
            original_name = stig_file.filename.upper()
            if 'RHEL_9' in original_name or 'RHEL9' in original_name or 'V2R6' in original_name:
                product = 'rhel9'
            elif 'RHEL_8' in original_name or 'RHEL8' in original_name or 'V2R5' in original_name:
                product = 'rhel8'
            elif 'WINDOWS_11' in original_name or 'WINDOWS11' in original_name:
                product = 'windows11'
            elif 'WINDOWS_SERVER_2022' in original_name or 'WINDOWS2022' in original_name:
                product = 'windows2022'
            elif 'WINDOWS_SERVER_2019' in original_name:
                product = 'windows2019'
            elif 'CISCO_IOS_ROUTER' in original_name or 'IOS_ROUTER' in original_name:
                product = 'cisco_ios_router'
            elif 'CISCO_IOS_SWITCH' in original_name or 'IOS_SWITCH' in original_name:
                product = 'cisco_ios_switch'
            elif 'CISCO_NX-OS' in original_name or 'NXOS' in original_name:
                product = 'cisco_nxos_switch'
            elif 'CISCO_ISE' in original_name or 'ISE' in original_name:
                product = 'cisco_ise'
        
        # Fallback to rhel9 if still unknown
        if product == 'unknown':
            product = 'rhel9'
            logger.warning(f"Could not detect product from filename, defaulting to rhel9")
        
        # Calculate statistics (handle all automation level variations)
        total_controls = len(controls_dict)
        automated = sum(1 for c in controls_dict if c.get('automation_level') in ['automated', 'automatable', 'scannable_with_nessus'])
        manual_only = sum(1 for c in controls_dict if c.get('automation_level') in ['manual_only', 'manual', 'not_scannable_with_nessus'])
        unknown = sum(1 for c in controls_dict if c.get('automation_level') == 'unknown')
        
        automation_source = controls_dict[0].get('automation_source', 'none') if controls_dict else 'none'
        logger.info(f"Automation classification (source: {automation_source}):")
        logger.info(f"  - Automated: {automated} ({int(automated/total_controls*100) if total_controls > 0 else 0}%)")
        logger.info(f"  - Manual-only: {manual_only} ({int(manual_only/total_controls*100) if total_controls > 0 else 0}%)")
        if unknown > 0:
            logger.info(f"  - Unknown: {unknown} ({int(unknown/total_controls*100) if total_controls > 0 else 0}%)")
        
        # Generate artifacts
        ansible_dir = app.config['OUTPUT_FOLDER'] / 'ansible'
        ctp_dir = app.config['OUTPUT_FOLDER'] / 'ctp'
        
        hardening_path = ansible_dir / f"stig_{product}_hardening.yml"
        checker_path = ansible_dir / f"stig_{product}_checker.yml"
        ctp_path = ctp_dir / f"stig_{product}_ctp.csv"
        
        # Generate using new scripts
        logger.info("Generating hardening playbook...")
        generate_hardening_playbook(controls_dict, hardening_path, product)
        
        logger.info("Generating checker playbook...")
        generate_checker_playbook(controls_dict, checker_path, product)
        
        logger.info("Generating CTP document...")
        generate_ctp_csv(controls_dict, ctp_path, manual_only=True)
        
        # Return relative paths from output folder (relative to BASE_DIR)
        # These paths will be used in the download route, so they should be relative to OUTPUT_FOLDER
        output_folder_rel = app.config['OUTPUT_FOLDER'].relative_to(BASE_DIR)
        
        return jsonify({
            'success': True,
            'message': f'Generation complete! Generated artifacts for {product}',
            'product': product,
            'stats': {
                'total_controls': total_controls,
                'automated': automated,
                'manual_only': manual_only,
                'unknown': unknown if 'unknown' in locals() else 0,
                'automation_source': automation_source
            },
            'files': {
                # Return paths relative to OUTPUT_FOLDER (not BASE_DIR)
                'hardening': f"ansible/stig_{product}_hardening.yml",
                'checker': f"ansible/stig_{product}_checker.yml",
                'ctp': f"ctp/stig_{product}_ctp.csv"
            }
        })
        
    except Exception as e:
        logger.error(f"Error during generation: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# Cache for loaded JSON files to avoid reloading on every search
_json_cache = {}
_json_cache_timestamps = {}


def _load_json_file(json_file: Path) -> list[dict]:
    """Load JSON file with caching based on file modification time."""
    mtime = json_file.stat().st_mtime
    
    # Check if we have a cached version that's still valid
    if json_file in _json_cache:
        cached_mtime = _json_cache_timestamps.get(json_file)
        if cached_mtime == mtime:
            return _json_cache[json_file]
    
    # Load and cache
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            controls = json.load(f)
        _json_cache[json_file] = controls
        _json_cache_timestamps[json_file] = mtime
        return controls
    except Exception as e:
        logger.error(f"Error loading {json_file}: {e}")
        raise


@app.route('/api/search', methods=['GET', 'POST'])
def search():
    """Search STIG controls from JSON files."""
    try:
        # Get query from various sources
        query = None
        if request.method == 'GET':
            query = request.args.get('q')
        elif request.method == 'POST':
            if request.is_json and request.json:
                query = request.json.get('q')
            else:
                query = request.form.get('q')
        
        if not query:
            return jsonify({'error': 'No search query provided'}), 400
        
        # Require minimum query length to avoid expensive searches
        if len(query.strip()) < 2:
            return jsonify({'error': 'Query must be at least 2 characters'}), 400
        
        query_lower = query.lower().strip()
        results = []
        
        # Search in JSON files in data/json directory
        json_dir = BASE_DIR / 'data' / 'json'
        if not json_dir.exists():
            return jsonify({'error': 'No JSON data directory found'}), 404
        
        # Find all JSON files
        json_files = list(json_dir.glob('*.json'))
        
        if not json_files:
            return jsonify({'error': 'No JSON files found'}), 404
        
        # Search in each JSON file (using cache)
        for json_file in json_files:
            try:
                controls = _load_json_file(json_file)
                
                # Search through controls - optimized
                for control in controls:
                    # Quick field checks first (most likely to match)
                    if (query_lower in str(control.get('id', '')).lower() or
                        query_lower in str(control.get('sv_id', '')).lower() or
                        query_lower in str(control.get('vul_id', '')).lower() or
                        query_lower in str(control.get('title', '')).lower()):
                        result = dict(control)
                        result['source_file'] = json_file.name
                        results.append(result)
                        continue
                    
                    # Only do expensive text search if we haven't found enough results
                    if len(results) < 100:
                        # Search in longer text fields
                        if (query_lower in str(control.get('description', '')).lower() or
                            query_lower in str(control.get('category', '')).lower()):
                            result = dict(control)
                            result['source_file'] = json_file.name
                            results.append(result)
            
            except Exception as e:
                logger.warning(f"Error reading {json_file}: {e}")
                continue
        
        # Limit results early to avoid large response
        limited_results = results[:100]
        
        return jsonify({
            'success': True,
            'query': query,
            'count': len(limited_results),
            'total_matches': len(results),
            'results': limited_results
        })
        
    except Exception as e:
        logger.error(f"Error during search: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Clear the JSON cache (useful after updating JSON files)."""
    try:
        _json_cache.clear()
        _json_cache_timestamps.clear()
        logger.info("JSON cache cleared")
        return jsonify({'success': True, 'message': 'Cache cleared'})
    except Exception as e:
        logger.error(f"Error clearing cache: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/download/<path:filename>')
def download(filename):
    """Download generated file."""
    try:
        # Resolve paths to absolute for security check
        file_path = (app.config['OUTPUT_FOLDER'] / filename).resolve()
        output_folder = app.config['OUTPUT_FOLDER'].resolve()
        
        # Security: ensure file is within output folder (prevent path traversal)
        try:
            file_path.relative_to(output_folder)
        except ValueError:
            logger.error(f"Security violation: Attempted to access file outside output folder: {filename}")
            return jsonify({'error': 'Invalid file path'}), 403
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=file_path.name
        )
    except Exception as e:
        logger.error(f"Error downloading file: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("=" * 60)
    print("STIG Generator Web Server")
    print("=" * 60)
    print("Starting server on http://localhost:4002")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=4002, debug=False, threaded=True)

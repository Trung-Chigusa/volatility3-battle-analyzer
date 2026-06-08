"""Quick test to see if Volatility3 can analyze the memory dump"""
import sys
from pathlib import Path

# Add volatility3 to path
sys.path.insert(0, str(Path(__file__).parent / "volatility3-2.26.2"))

try:
    print("Importing volatility3...")
    from volatility3 import framework
    from volatility3.framework import contexts, automagic
    import volatility3.plugins
    
    print("Creating context...")
    context = contexts.Context()
    
    # Set memory dump location
    dump_file = r"C:\Users\Ninym\Desktop\FOR\CSCV\Memory_Tool\volatility3-2.26.2\mem.raw"
    print(f"Setting dump file: {dump_file}")
    
    from volatility3.framework.interfaces import configuration
    location_path = configuration.path_join("automagic", "LayerStacker", "single_location")
    context.config[location_path] = f"file:{dump_file}"
    
    print("Loading plugins...")
    failures = framework.import_files(volatility3.plugins, True)
    print(f"Plugin failures: {failures}")
    
    plugin_list = framework.list_plugins()
    print(f"Loaded {len(plugin_list)} plugins")
    
    # Try pslist (simpler than netscan)
    print("\n=== Testing windows.pslist.PsList ===")
    plugin_class = plugin_list.get("windows.pslist.PsList")
    if not plugin_class:
        print("ERROR: pslist plugin not found!")
        sys.exit(1)
    
    print("Getting automagics...")
    available_automagics = automagic.available(context)
    print(f"Found {len(available_automagics)} automagics")
    
    print("Constructing plugin...")
    from volatility3.cli import PrintedProgress
    from volatility3.framework.plugins import construct_plugin
    
    def dummy_progress(progress, description):
        print(f"  Progress: {progress:.1f}% - {description}")
    
    constructed = construct_plugin(
        context,
        automagic.choose_automagic(available_automagics, plugin_class),
        plugin_class,
        "plugins",
        dummy_progress,
        lambda x: open(x, "wb")
    )
    
    print("Running plugin...")
    treegrid = constructed.run()
    
    print("Converting results...")
    results = []
    def visitor(node, accumulator):
        row = {}
        for column_index, column in enumerate(treegrid.columns):
            value = node.values[column_index]
            row[column.name] = str(value) if hasattr(value, '__str__') else value
        results.append(row)
        return accumulator
    
    treegrid.populate(visitor, None)
    
    print(f"\n=== SUCCESS! Found {len(results)} processes ===")
    for i, proc in enumerate(results[:5]):  # Show first 5
        print(f"{i+1}. PID={proc.get('PID', '?')} Name={proc.get('ImageFileName', '?')}")
    
except Exception as e:
    print(f"\n=== ERROR ===")
    print(f"{type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)


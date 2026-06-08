"""Volatility3 integration wrapper"""
import sys
import os
import logging
import io
from typing import Dict, List, Optional, Callable, Any, Type, TYPE_CHECKING
from pathlib import Path

if TYPE_CHECKING:
    from volatility3.framework.interfaces import plugins

# Add volatility3 to path if needed
# When running as exe, volatility3 is in the extracted temp directory
if getattr(sys, 'frozen', False):
    # Running as compiled exe
    base_path = Path(sys._MEIPASS)
    volatility3_path = base_path / "volatility3-2.26.2"
else:
    # Running as script
    volatility3_path = Path(__file__).parent.parent.parent / "volatility3-2.26.2"

if str(volatility3_path) not in sys.path:
    sys.path.insert(0, str(volatility3_path))

try:
    import volatility3.framework as framework
    from volatility3.framework import contexts, automagic, exceptions, constants
    from volatility3.framework.interfaces import plugins, configuration
    from volatility3.framework.plugins import construct_plugin
    import volatility3.plugins
    VOLATILITY_AVAILABLE = True
except ImportError as e:
    VOLATILITY_AVAILABLE = False
    IMPORT_ERROR = str(e)

logger = logging.getLogger(__name__)


from volatility3.framework.interfaces import plugins as plugin_interfaces

class FileHandler(plugin_interfaces.FileHandlerInterface):
    """File handler that stores data in memory"""
    def __init__(self, filename: str):
        self._closed = False  # Use _closed as backing field
        super().__init__(plugin_interfaces.FileHandlerInterface.sanitize_filename(filename))
        self.filename = filename
        self.data = io.BytesIO()
    
    def writelines(self, lines):
        for line in lines:
            self.write(line)
    
    def write(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.data.write(data)
        return len(data)

    def seek(self, offset, whence=os.SEEK_SET):
        return self.data.seek(offset, whence)

    def tell(self):
        return self.data.tell()

    def readable(self):
        return True

    def writable(self):
        return True

    def seekable(self):
        return True

    def getvalue(self):
        return self.data.getvalue()
    
    def close(self):
        if not self._closed:
            self.data.close()
            self._closed = True
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
        return False
    
    @property
    def closed(self):
        return self._closed
    
    @closed.setter
    def closed(self, value):
        self._closed = value

class VolatilityRunner:
    """Wrapper class for running volatility3 plugins programmatically"""
    
    def __init__(self, dump_file: str, progress_callback: Optional[Callable[[float, str], None]] = None):
        """Initialize volatility3 context for a memory dump
        
        Args:
            dump_file: Path to memory dump file
            progress_callback: Optional callback function(progress: float, description: str)
        """
        if not VOLATILITY_AVAILABLE:
            raise RuntimeError(f"Volatility3 not available: {IMPORT_ERROR}")
        
        self.dump_file = os.path.abspath(dump_file)
        if not os.path.exists(self.dump_file):
            raise FileNotFoundError(f"Memory dump file not found: {self.dump_file}")
        
        self.progress_callback = progress_callback or (lambda p, d: None)
        self.context = None
        self.base_config_path = "plugins"
        self.plugin_list = {}
        self.available_automagics = []
        self._initialized = False
        
    def _log_progress(self, progress: float, description: str):
        """Internal progress logging"""
        logger.debug(f"Progress: {progress:.2f}% - {description}")
        self.progress_callback(progress, description)
    
    def initialize(self) -> bool:
        """Initialize volatility3 framework and load plugins
        
        Returns:
            True if initialization successful
        """
        if self._initialized:
            return True
        
        try:
            self._log_progress(0, "Initializing Volatility3 framework...")
            
            # Suppress Volatility3's internal logging to reduce overhead
            import logging as internal_logging
            volatility_logger = internal_logging.getLogger('volatility3')
            volatility_logger.setLevel(internal_logging.WARNING)  # Only show warnings/errors
            
            # Also suppress automagic logging (which prints progress)
            automagic_logger = internal_logging.getLogger('volatility3.framework.automagic')
            automagic_logger.setLevel(internal_logging.ERROR)  # Only critical errors
            
            # Require interface version
            framework.require_interface_version(2, 0, 0)
            
            # Create context
            self.context = contexts.Context()
            
            self._configure_single_location()
            
            # Import plugins
            self._log_progress(10, "Loading plugins...")
            failures = framework.import_files(volatility3.plugins, True)
            if failures:
                logger.warning(f"Some plugins failed to load: {failures}")
            
            # Get available plugins
            self.plugin_list = framework.list_plugins()
            logger.info(f"Loaded {len(self.plugin_list)} plugins")
            
            # Get available automagics
            self.available_automagics = automagic.available(self.context)
            logger.info(f"Found {len(self.available_automagics)} automagic modules")
            
            self._initialized = True
            self._log_progress(100, "Initialization complete")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Volatility3: {e}", exc_info=True)
            raise
    
    def get_available_plugins(self) -> Dict[str, Type[Any]]:
        """Get dictionary of available plugin names and classes"""
        if not self._initialized:
            self.initialize()
        return self.plugin_list.copy()
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific plugin"""
        if not self._initialized:
            self.initialize()
        
        plugin_class = self.plugin_list.get(plugin_name)
        if not plugin_class:
            return None
        
        try:
            reqs = plugin_class.get_requirements()
            return {
                'name': plugin_name,
                'class': plugin_class,
                'requirements': reqs,
                'description': getattr(plugin_class, '__doc__', 'No description'),
            }
        except Exception as e:
            logger.error(f"Error getting plugin info for {plugin_name}: {e}")
            return None
    
    def _configure_single_location(self):
        """Set the memory image location for automagic stacker."""
        if not self.context:
            return
        location = f"file:{self.dump_file}"
        stacker_path = configuration.path_join("automagic", "LayerStacker", "single_location")
        self.context.config[stacker_path] = location
        logger.debug("Configured automagic single_location=%s", location)

    @staticmethod
    def create_disk_file_handler(output_dir: str):
        """Create a FileHandler class that writes outputs to disk"""
        base_directory = Path(output_dir)
        base_directory.mkdir(parents=True, exist_ok=True)
        
        class DiskFileHandler(plugin_interfaces.FileHandlerInterface):
            output_dir = base_directory
            created_files: List[str] = []
            
            def __init__(self, filename: str):
                sanitized = plugin_interfaces.FileHandlerInterface.sanitize_filename(filename)
                super().__init__(sanitized)
                self._closed = False
                DiskFileHandler.output_dir.mkdir(parents=True, exist_ok=True)
                self.file_path = DiskFileHandler.output_dir / sanitized
                self.file_path.parent.mkdir(parents=True, exist_ok=True)
                self._handle = open(self.file_path, "wb")
                DiskFileHandler.created_files.append(str(self.file_path))
            
            def write(self, data):
                if isinstance(data, str):
                    data = data.encode("utf-8")
                self._handle.write(data)
                return len(data)

            def seek(self, offset, whence=os.SEEK_SET):
                return self._handle.seek(offset, whence)

            def tell(self):
                return self._handle.tell()

            def flush(self):
                return self._handle.flush()

            def readable(self):
                return False

            def writable(self):
                return True

            def seekable(self):
                return True
            
            def writelines(self, lines):
                for line in lines:
                    self.write(line)
            
            def close(self):
                if not getattr(self, "_closed", False):
                    try:
                        self._handle.close()
                    finally:
                        self._closed = True
            
            @property
            def closed(self):
                return getattr(self, "_closed", False)
            
            @closed.setter
            def closed(self, value):
                self._closed = value
        
        DiskFileHandler.created_files = []
        return DiskFileHandler

    def run_plugin(
        self,
        plugin_name: str,
        plugin_args: Optional[Dict[str, Any]] = None,
        base_config_path: str = "plugins",
        file_handler_cls: Optional[Type[plugin_interfaces.FileHandlerInterface]] = None
    ) -> Optional[Any]:
        """Run a volatility3 plugin and return results as TreeGrid
        
        Args:
            plugin_name: Name of the plugin to run
            plugin_args: Optional dictionary of plugin-specific arguments
            base_config_path: Configuration path for the plugin
            
        Returns:
            TreeGrid object with results, or None if failed
        """
        logger.info("=" * 60)
        logger.info("RUNNING PLUGIN: %s", plugin_name)
        logger.info("Args: %s", plugin_args)
        logger.info("=" * 60)
        
        if not self._initialized:
            logger.info("Not initialized, calling initialize()...")
            self.initialize()
        
        plugin_class = self.plugin_list.get(plugin_name)
        if not plugin_class:
            raise ValueError(f"Plugin '{plugin_name}' not found")
        
        logger.info("Plugin class found: %s", plugin_class)
        
        try:
            self._log_progress(0, f"Preparing plugin: {plugin_name}")
            logger.info("Preparing plugin...")
            
            # Set up configuration
            plugin_config_path = configuration.path_join(base_config_path, plugin_class.__name__)
            
            # Ensure automagic knows the single location
            self._configure_single_location()

            # Plugin-specific location configuration
            plugin_location_path = configuration.path_join(plugin_config_path, "location")
            self.context.config[plugin_location_path] = f"file:{self.dump_file}"
            logger.debug("Configured plugin location at %s", plugin_location_path)
            
            # Set any additional plugin arguments
            if plugin_args:
                for key, value in plugin_args.items():
                    arg_path = configuration.path_join(plugin_config_path, key)
                    self.context.config[arg_path] = value
            
            # Choose appropriate automagics for this plugin
            logger.info("Choosing automagics for plugin...")
            chosen_automagics = automagic.choose_automagic(self.available_automagics, plugin_class)
            logger.info(f"Selected {len(chosen_automagics)} automagics")
            
            # Construct and run plugin
            self._log_progress(20, f"Running plugin: {plugin_name}")
            logger.info("Constructing plugin...")
            
            try:
                # Use framework's construct_plugin which handles automagics correctly
                handler_class = file_handler_cls or FileHandler
                constructed_plugin = construct_plugin(
                    self.context,
                    chosen_automagics,
                    plugin_class,
                    base_config_path,
                    self._log_progress,
                    handler_class
                )
                logger.info("Plugin constructed successfully")
            except Exception as construct_error:
                logger.error(f"Failed to construct plugin: {construct_error}", exc_info=True)
                raise
            
            logger.info("Now executing plugin.run() - this may take several minutes for large memory dumps...")
            self._log_progress(80, f"Executing plugin: {plugin_name}")
            
            try:
                import time
                start_time = time.time()
                treegrid = constructed_plugin.run()
                elapsed = time.time() - start_time
                logger.info(f"Plugin execution completed in {elapsed:.1f}s, treegrid received")
            except Exception as run_error:
                logger.error(f"Failed to execute plugin.run(): {run_error}", exc_info=True)
                raise
            
            self._log_progress(100, f"Plugin {plugin_name} completed")
            return treegrid
            
        except exceptions.UnsatisfiedException as e:
            logger.error(f"Plugin requirements not satisfied: {e}")
            raise
        except Exception as e:
            logger.error(f"Error running plugin {plugin_name}: {e}", exc_info=True)
            raise
    
    def treegrid_to_list(self, treegrid: Any) -> List[Dict[str, Any]]:
        """Convert TreeGrid to list of dictionaries
        
        Args:
            treegrid: TreeGrid object from plugin
            
        Returns:
            List of dictionaries, one per row
        """
        results = []
        
        def visitor(node, accumulator):
            row = {}
            for column_index, column in enumerate(treegrid.columns):
                value = node.values[column_index]
                # Handle special value types
                if hasattr(value, 'value'):
                    row[column.name] = value.value
                elif hasattr(value, '__str__'):
                    row[column.name] = str(value)
                else:
                    row[column.name] = value
            results.append(row)
            return accumulator
        
        try:
            treegrid.populate(visitor, None)
        except Exception as e:
            logger.error(f"Error converting TreeGrid: {e}", exc_info=True)
        
        return results
    
    def run_plugin_to_list(
        self,
        plugin_name: str,
        plugin_args: Optional[Dict[str, Any]] = None,
        file_handler_cls: Optional[Type[plugin_interfaces.FileHandlerInterface]] = None
    ) -> List[Dict[str, Any]]:
        """Run a plugin and return results as a list of dictionaries
        
        Convenience method that combines run_plugin and treegrid_to_list
        """
        logger.info("run_plugin_to_list() called for plugin: %s", plugin_name)
        treegrid = self.run_plugin(plugin_name, plugin_args, file_handler_cls=file_handler_cls)
        logger.info("run_plugin() returned, converting treegrid to list...")
        if treegrid:
            result_list = self.treegrid_to_list(treegrid)
            logger.info("Converted to list with %d items", len(result_list))
            return result_list
        logger.warning("treegrid is None/empty")
        return []


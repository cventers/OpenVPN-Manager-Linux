#!/usr/bin/env python3
"""
VPN Manager for Exceleron OpenVPN Configurations
Advanced connection manager with fuzzy matching, session management, and hooks
"""

import argparse
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click
import yaml
from fuzzywuzzy import fuzz, process


class VPNManager:
    def __init__(self, config_path: str = "/home/chase/ovpn/vpn-config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.base_dir = Path(self.config['base_dir'])
        self._setup_logging()
        
    def _load_config(self) -> Dict:
        """Load YAML configuration file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            click.echo(f"Config file not found: {self.config_path}", err=True)
            sys.exit(1)
        except yaml.YAMLError as e:
            click.echo(f"Error parsing config file: {e}", err=True)
            sys.exit(1)
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_config = self.config.get('logging', {})
        log_file = log_config.get('file', '/tmp/vpn-manager.log')
        log_level = getattr(logging, log_config.get('level', 'INFO'))
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _make_profile_safe(self, profile: str) -> str:
        """Convert profile name to safe session name"""
        return re.sub(r'[^a-zA-Z0-9_-]', '_', profile)
    
    def _resolve_profile(self, input_str: str) -> Optional[Tuple[str, str, str]]:
        """
        Resolve fuzzy input to location/network/file
        Returns (location, network, file_path) or None
        """
        # Try exact match first
        for location, loc_config in self.config['profiles'].items():
            for network, net_config in loc_config['networks'].items():
                # Check exact network name
                if network == input_str:
                    file_path = self.base_dir / loc_config['directory'] / net_config['file']
                    return location, network, str(file_path)
                
                # Check aliases
                for alias in net_config.get('aliases', []):
                    if alias == input_str:
                        file_path = self.base_dir / loc_config['directory'] / net_config['file']
                        return location, network, str(file_path)
        
        # Try location + network fuzzy matching
        parts = input_str.split()
        if len(parts) >= 2:
            location_part = parts[0]
            network_part = ' '.join(parts[1:])
            
            # Simple exact match instead of fuzzy match to avoid Click issues
            if location_part in self.config['profiles']:
                location = location_part
                loc_config = self.config['profiles'][location]
                
                # Check for exact network match or alias match
                for network, net_config in loc_config['networks'].items():
                    if network == network_part or network_part in net_config.get('aliases', []):
                        file_path = self.base_dir / loc_config['directory'] / net_config['file']
                        return location, network, str(file_path)
        
        # Fuzzy matching disabled due to Click interaction issues
        # TODO: Implement safer fuzzy matching that doesn't interfere with Click
        return None
    
    def _get_session_name(self, location: str, network: str) -> str:
        """Generate session name from template"""
        profile = f"{location}_{network}"
        profile_safe = self._make_profile_safe(profile)
        return self.config['session']['name_template'].format(profile_safe=profile_safe)
    
    def _run_hooks(self, hook_type: str) -> bool:
        """Run hooks of specified type"""
        hooks = self.config['hooks'].get(hook_type, [])
        for hook in hooks:
            name = hook['name']
            command = hook['command']
            required = hook.get('required', False)
            description = hook.get('description', '')
            
            self.logger.info(f"Running {hook_type} hook: {name} - {description}")
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode != 0:
                    error_msg = f"Hook {name} failed: {result.stderr}"
                    self.logger.error(error_msg)
                    if required:
                        click.echo(f"Required hook failed: {error_msg}", err=True)
                        return False
                    else:
                        click.echo(f"Optional hook failed: {error_msg}", err=True)
                else:
                    self.logger.info(f"Hook {name} completed successfully")
            except subprocess.TimeoutExpired:
                error_msg = f"Hook {name} timed out"
                self.logger.error(error_msg)
                if required:
                    click.echo(f"Required hook timed out: {error_msg}", err=True)
                    return False
                else:
                    click.echo(f"Optional hook timed out: {error_msg}", err=True)
            except Exception as e:
                error_msg = f"Hook {name} error: {e}"
                self.logger.error(error_msg)
                if required:
                    click.echo(f"Required hook error: {error_msg}", err=True)
                    return False
                else:
                    click.echo(f"Optional hook error: {error_msg}", err=True)
        
        return True
    
    def _check_session_exists(self, session_name: str) -> bool:
        """Check if session exists"""
        session_type = self.config['session']['type']
        try:
            if session_type == 'screen':
                result = subprocess.run(
                    ['screen', '-ls'],
                    capture_output=True,
                    text=True
                )
                return session_name in result.stdout
            elif session_type == 'tmux':
                result = subprocess.run(
                    ['tmux', 'list-sessions'],
                    capture_output=True,
                    text=True
                )
                return session_name in result.stdout
        except Exception:
            return False
        return False
    
    def _kill_session(self, session_name: str) -> bool:
        """Kill existing session"""
        session_type = self.config['session']['type']
        try:
            if session_type == 'screen':
                result = subprocess.run(
                    ['screen', '-S', session_name, '-X', 'kill'],
                    capture_output=True
                )
                return result.returncode == 0
            elif session_type == 'tmux':
                result = subprocess.run(
                    ['tmux', 'kill-session', '-t', session_name],
                    capture_output=True
                )
                return result.returncode == 0
        except Exception:
            return False
        return False
    
    def connect(self, profile_input: str) -> bool:
        """Connect to VPN profile"""
        # Resolve profile
        resolved = self._resolve_profile(profile_input)
        if not resolved:
            suggestions = self._get_suggestions(profile_input)
            click.echo(f"Profile '{profile_input}' not found.")
            if suggestions:
                click.echo("Did you mean:")
                for suggestion in suggestions:
                    click.echo(f"  {suggestion}")
            return False
        
        location, network, file_path = resolved
        
        # Check if file exists
        if not os.path.exists(file_path):
            click.echo(f"VPN config file not found: {file_path}", err=True)
            return False
        
        session_name = self._get_session_name(location, network)
        
        # Check for existing sessions and simultaneity rules
        if not self._check_simultaneity(location, network, session_name):
            return False
        
        # Run pre-connect hooks
        if not self._run_hooks('pre_connect'):
            return False
        
        # Start VPN connection
        session_type = self.config['session']['type']
        daemon_mode = self.config['session'].get('daemon_mode', True)
        startup_delay = self.config['session'].get('startup_delay', 10)
        
        try:
            if session_type == 'screen':
                cmd = ['screen']
                if daemon_mode:
                    cmd.extend(['-d', '-m'])
                cmd.extend(['-S', session_name, 'sudo', 'openvpn', '--config', file_path])
                
                result = subprocess.run(cmd, cwd=str(self.base_dir))
                if result.returncode == 0:
                    click.echo(f"Started VPN connection: {location} {network}")
                    click.echo(f"Session: {session_name}")
                    
                    if startup_delay > 0:
                        click.echo(f"Waiting {startup_delay}s for connection to stabilize...")
                        time.sleep(startup_delay)
                    
                    # Run post-connect hooks
                    self._run_hooks('post_connect')
                    return True
                    
            elif session_type == 'tmux':
                cmd = ['tmux', 'new-session', '-d', '-s', session_name, 
                       'sudo', 'openvpn', '--config', file_path]
                
                result = subprocess.run(cmd, cwd=str(self.base_dir))
                if result.returncode == 0:
                    click.echo(f"Started VPN connection: {location} {network}")
                    click.echo(f"Session: {session_name}")
                    
                    if startup_delay > 0:
                        click.echo(f"Waiting {startup_delay}s for connection to stabilize...")
                        time.sleep(startup_delay)
                    
                    # Run post-connect hooks
                    self._run_hooks('post_connect')
                    return True
        
        except Exception as e:
            click.echo(f"Failed to start VPN connection: {e}", err=True)
            return False
        
        return False
    
    def _check_simultaneity(self, location: str, network: str, session_name: str) -> bool:
        """Check simultaneity rules and handle existing connections"""
        loc_config = self.config['profiles'][location]
        net_config = loc_config['networks'][network]
        
        # Check if this specific session already exists
        if self._check_session_exists(session_name):
            if not net_config.get('allow_multiple', False):
                click.echo(f"Connection already exists: {location} {network}")
                response = click.confirm("Kill existing connection and reconnect?")
                if response:
                    if not self._kill_session(session_name):
                        click.echo("Failed to kill existing session", err=True)
                        return False
                else:
                    return False
        
        # Check location simultaneity rules
        if not loc_config.get('allow_simultaneous', False):
            # Check for any existing sessions from this location
            existing_sessions = self._get_location_sessions(location)
            if existing_sessions:
                click.echo(f"Location '{location}' does not allow simultaneous connections.")
                click.echo("Existing connections:")
                for sess in existing_sessions:
                    click.echo(f"  {sess}")
                response = click.confirm("Kill all existing connections from this location?")
                if response:
                    for sess in existing_sessions:
                        self._kill_session(sess)
                else:
                    return False
        
        return True
    
    def _get_location_sessions(self, location: str) -> List[str]:
        """Get all active sessions for a location"""
        sessions = []
        loc_config = self.config['profiles'][location]
        
        for network in loc_config['networks'].keys():
            session_name = self._get_session_name(location, network)
            if self._check_session_exists(session_name):
                sessions.append(session_name)
        
        return sessions
    
    def _get_suggestions(self, input_str: str) -> List[str]:
        """Get fuzzy match suggestions"""
        all_choices = []
        for location, loc_config in self.config['profiles'].items():
            for network, net_config in loc_config['networks'].items():
                all_choices.append(f"{location} {network}")
                for alias in net_config.get('aliases', []):
                    all_choices.append(f"{location} {alias}")
        
        matches = process.extract(
            input_str,
            all_choices,
            scorer=fuzz.ratio,
            limit=self.config['fuzzy_matching']['max_suggestions']
        )
        
        return [match[0] for match in matches if match[1] >= 50]  # Lower threshold for suggestions
    
    def disconnect(self, profile_input: str = None) -> bool:
        """Disconnect VPN profile(s)"""
        if profile_input:
            # Disconnect specific profile
            self.logger.info(f"Attempting to disconnect profile: '{profile_input}'")
            resolved = self._resolve_profile(profile_input)
            if not resolved:
                self.logger.error(f"Profile resolution failed for: '{profile_input}'")
                click.echo(f"Profile '{profile_input}' not found.", err=True)
                return False
            
            location, network, _ = resolved
            session_name = self._get_session_name(location, network)
            
            if not self._check_session_exists(session_name):
                click.echo(f"No active connection found for: {location} {network}")
                return False
            
            # Run pre-disconnect hooks
            self._run_hooks('pre_disconnect')
            
            if self._kill_session(session_name):
                click.echo(f"Disconnected: {location} {network}")
                # Run post-disconnect hooks
                self._run_hooks('post_disconnect')
                return True
            else:
                click.echo(f"Failed to disconnect: {location} {network}", err=True)
                return False
        else:
            # Disconnect all VPN connections
            self._run_hooks('pre_disconnect')
            
            # Kill all openvpn processes
            try:
                subprocess.run(['sudo', 'pkill', 'openvpn'], check=False)
                click.echo("Disconnected all VPN connections")
                
                # Run post-disconnect hooks
                self._run_hooks('post_disconnect')
                return True
            except Exception as e:
                click.echo(f"Failed to disconnect all connections: {e}", err=True)
                return False
    
    def status(self) -> bool:
        """Show status of VPN connections"""
        session_type = self.config['session']['type']
        active_sessions = []
        
        # Get all possible sessions
        all_sessions = []
        for location, loc_config in self.config['profiles'].items():
            for network in loc_config['networks'].keys():
                session_name = self._get_session_name(location, network)
                all_sessions.append((location, network, session_name))
        
        # Check which sessions are active
        for location, network, session_name in all_sessions:
            if self._check_session_exists(session_name):
                active_sessions.append((location, network, session_name))
        
        if not active_sessions:
            click.echo("No active VPN connections")
            return True
        
        click.echo("Active VPN connections:")
        for location, network, session_name in active_sessions:
            click.echo(f"  {location} {network} ({session_name})")
            
            # Get session details
            try:
                if session_type == 'screen':
                    # Try to get screen log or status
                    result = subprocess.run(
                        ['screen', '-S', session_name, '-X', 'hardcopy', '-h', '/tmp/screen_output'],
                        capture_output=True
                    )
                elif session_type == 'tmux':
                    # Get tmux pane content
                    result = subprocess.run(
                        ['tmux', 'capture-pane', '-t', session_name, '-p'],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        # Show last few lines
                        for line in lines[-3:]:
                            if line.strip():
                                click.echo(f"    {line.strip()}")
            except Exception:
                pass
        
        return True
    
    def list_profiles(self) -> bool:
        """List all available profiles"""
        click.echo("Available VPN profiles:")
        
        for location, loc_config in self.config['profiles'].items():
            click.echo(f"\n{location} - {loc_config['description']}")
            for network, net_config in loc_config['networks'].items():
                aliases_str = ""
                if net_config.get('aliases'):
                    aliases_str = f" (aliases: {', '.join(net_config['aliases'])})"
                click.echo(f"  {network} - {net_config['description']}{aliases_str}")
        
        return True


@click.group()
@click.option('--config', default='/home/chase/ovpn/vpn-config.yaml', help='Config file path')
@click.pass_context
def cli(ctx, config):
    """VPN Manager for Exceleron OpenVPN Configurations"""
    ctx.ensure_object(dict)
    ctx.obj['manager'] = VPNManager(config)


@cli.command()
@click.argument('profile')
@click.pass_context
def connect(ctx, profile):
    """Connect to a VPN profile"""
    manager = ctx.obj['manager']
    success = manager.connect(profile)
    sys.exit(0 if success else 1)


@cli.command()
@click.argument('profile', required=False)
@click.pass_context
def disconnect(ctx, profile):
    """Disconnect from VPN profile(s)"""
    manager = ctx.obj['manager']
    success = manager.disconnect(profile)
    sys.exit(0 if success else 1)


@cli.command()
@click.pass_context
def status(ctx):
    """Show status of VPN connections"""
    manager = ctx.obj['manager']
    success = manager.status()
    sys.exit(0 if success else 1)


@cli.command()
@click.pass_context
def list(ctx):
    """List all available VPN profiles"""
    manager = ctx.obj['manager']
    success = manager.list_profiles()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    cli()
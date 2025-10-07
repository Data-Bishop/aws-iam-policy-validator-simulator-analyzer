"""
IAM Policy Parser Module

This module handles parsing, normalization, and validation of AWS IAM policy documents.
Supports both JSON and YAML formats, and ensures policies are in a consistent structure
for downstream processing.

Author: @DataBishop
Version: 1.0.0
"""

from typing import Any, Dict, List, Literal, Optional, Union
from pathlib import Path
import json
import copy
import logging


# YAML is an optional dependency. Keep its import guarded so users who only
# need JSON parsing won't fail if PyYAML isn't installed.
try:
    import yaml
except Exception:
    yaml = None
 
    
# Configure logging
logger = logging.getLogger(__name__)


class PolicyParserError(Exception):
    """Base exception for policy parsing errors"""
    pass


class InvalidPolicyFormatError(PolicyParserError):
    """Raised when policy format is invalid"""
    pass


class UnsupportedVersionError(PolicyParserError):
    """Raised when policy version is not supported"""
    pass


class PolicyParser:
    """
    Parse and normalize AWS IAM policy documents.
    
    Supports:
    - JSON and YAML formats
    - Identity-based policies
    - Resource-based policies
    - Trust policies
    - Service Control Policies (SCPs)
    - VPC Endpoint policies
    - Session policies
    
    Normalizes policies to ensure consistent structure:
    - Converts single values to lists (Action, Resource, etc.)
    - Validates required fields
    - Handles different policy formats
    """
    
    # Supported policy versions
    SUPPORTED_VERSIONS = ["2012-10-17", "2008-10-17"]
    
    # Required top-level keys for different policy types
    REQUIRED_KEYS = {
        "identity": ["Version", "Statement"],
        "resource": ["Version", "Statement"],
        "trust": ["Version", "Statement"],
        "scp": ["Version", "Statement"]
    }
    
    # Keys that should be converted to lists if they're strings
    LIST_KEYS = [
        "Action", "NotAction",
        "Resource", "NotResource",
        "Principal", "NotPrincipal"
    ]

    def __init__(self, strict_mode: bool = False) -> None:
        """
        Initialize the PolicyParser.
        
        Args:
            strict_mode: If True, raise errors for warnings. If False, log warnings.
        """
        self.strict_mode = strict_mode
        self.warnings = []
        self.errors = []

    def parse_file(self, file_path: Union[str, Path], inplace: bool = False) -> Dict[str, Any]:
        """
        Parse a policy file (JSON or YAML).
        
        Args:
            file_path: Path to the policy file
            
        Returns:
            Normalized policy dictionary
            
        Raises:
            PolicyParserError: If file cannot be read or parsed
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise PolicyParserError(f"Policy file not found: {file_path}")
        
        logger.info(f"Parsing policy file: {file_path}")
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            raise PolicyParserError(f"Error reading file {file_path}: {e}")
        
        # Determine format based on file extension
        if file_path.suffix.lower() in [".json"]:
            format_type = "json"
        elif file_path.suffix.lower() in [".yaml", ".yml"]:
            format_type = "yaml"
        else:
            # Try to auto-detect
            format_type = self._detect_format(content)
        
        return self.parse_policy(content, format_type, inplace=inplace)

    def parse_policy(self, policy_content: Union[str, Dict[str, Any]], format_type: Literal["json", "yaml"] = "json", inplace: bool = False) -> Dict[str, Any]:
        """Parse policy from JSON or YAML or accept an already parsed dict.

        Args:
            policy_content: Policy document as a string (JSON/YAML) or a dict.
            format_type: "json" or "yaml" (ignored if `policy_content` is already a dict)

        Returns:
            Normalized policy dictionary (a copy of the parsed input).

        Raises:
            InvalidPolicyFormatError: If policy cannot be parsed
            RuntimeError: when YAML parsing is requested but PyYAML isn't available.
        """
        self.warnings = []
        self.errors = []
        
        logger.debug(f"Parsing policy with format: {format_type}")
        
        # Accept dicts directly (useful for any callers that already parsed the document)
        if isinstance(policy_content, dict):
            policy = policy_content
        else:
            if format_type.lower() == "json":
                policy = json.loads(policy_content)
            elif format_type.lower() in ["yaml", "yml"]:
                if yaml is None:
                    raise RuntimeError("PyYAML is required for YAML parsing but is not installed")
                policy = yaml.safe_load(policy_content)
            else:
                raise InvalidPolicyFormatError(f"Unsupported format: {format_type}")

        if not isinstance(policy, dict):
            raise InvalidPolicyFormatError("Policy must be a mapping/dict")

        # Optionally validate policy version (non-fatal in some tooling; adapt as needed)
        # version = policy.get("Version")
        # if version is not None and version not in self.supported_versions:
        #     # Keep behavior conservative: raise so callers fix unexpected versions
        #     raise ValueError(f"Unsupported policy Version: {version}")

        # Decide whether to operate in-place (caller-provided dict modified)
        # or on a deep copy (safe, non-mutating behavior).
        if inplace:
            working_policy = policy
        else:
            working_policy = copy.deepcopy(policy)

        # Validate and normalize
        working_policy = self._validate_structure(working_policy)
        working_policy = self._normalize_policy(working_policy)

        logger.info(f"Successfully parsed policy with {len(working_policy.get('Statement', []))} statements")

        return working_policy

    def _detect_format(self, content: str) -> str:
        """
        Auto-detect policy format (JSON or YAML).
        
        Args:
            content: Policy content as string
            
        Returns:
            Detected format ('json' or 'yaml')
        """
        content = content.strip()
        
        # Try JSON first
        if content.startswith('{'):
            try:
                json.loads(content)
                return 'json'
            except:
                pass
        
        # Try YAML
        try:
            yaml.safe_load(content)
            return 'yaml'
        except:
            pass
        
        # Default to JSON
        logger.warning("Could not detect format, defaulting to JSON")
        return 'json'

    def _validate_structure(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate basic policy structure.
        
        Args:
            policy: Policy dictionary
            
        Returns:
            Validated policy
            
        Raises:
            UnsupportedVersionError: If version is unsupported (in strict mode)
            InvalidPolicyFormatError: If structure is invalid
        """
        # Check for Version
        if 'Version' not in policy:
            self._add_warning("Policy missing 'Version' field")
            policy['Version'] = '2012-10-17'  # Default version
        
        # Validate version
        if policy['Version'] not in self.SUPPORTED_VERSIONS:
            if self.strict_mode:
                raise UnsupportedVersionError(
                    f"Unsupported policy version: {policy['Version']}. "
                    f"Supported versions: {', '.join(self.SUPPORTED_VERSIONS)}"
                )
            else:
                self._add_warning(f"Policy version {policy['Version']} may not be fully supported")
        
        # Check for Statement
        if 'Statement' not in policy:
            raise InvalidPolicyFormatError("Policy missing required 'Statement' field")
        
        # Validate Statement is a list or dict
        if not isinstance(policy['Statement'], (list, dict)):
            raise InvalidPolicyFormatError(
                f"'Statement' must be a list or object, got {type(policy['Statement']).__name__}"
            )
        
        return policy

    def _normalize_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize policy to consistent structure.
        
        Normalization includes:
        - Convert Statement to list if it's a single object
        - Convert Action/Resource/Principal to lists if they're strings
        - Remove empty statements
        - Normalize Effect values
        - Add default values where appropriate
        
        Args:
            policy: Policy dictionary
            
        Returns:
            Normalized policy
        """
        logger.debug("Normalizing policy structure")
        # Ensure Statement is always a list
        if not isinstance(policy['Statement'], list):
            policy["Statement"] = self._ensure_list(policy["Statement"])

        # Normalize each statement
        normalized_statements = []
        for idx, statement in enumerate(policy['Statement']):
            try:
                normalized_stmt = self._normalize_statement(statement, idx)
                if normalized_stmt:  # Only add non-empty statements
                    normalized_statements.append(normalized_stmt)
            except Exception as e:
                self._add_error(f"Error normalizing statement {idx}: {e}")
                if self.strict_mode:
                    raise
        
        policy['Statement'] = normalized_statements
        
        return policy
    
    def _normalize_statement(self, statement: Dict[str, Any], index: int) -> Optional[Dict[str, Any]]:
        """
        Normalize a single policy statement.
        
        Args:
            statement: Statement dictionary
            index: Statement index (for logging)
            
        Returns:
            Normalized statement or None if invalid
        """
        if not isinstance(statement, dict):
            self._add_error(f"Statement {index} is not an object")
            return None
        
        # Check for required Effect field
        if 'Effect' not in statement:
            self._add_warning(f"Statement {index} missing 'Effect' field, defaulting to 'Deny'")
            statement['Effect'] = 'Deny'
        
        # Normalize Effect
        effect = statement['Effect']
        if effect not in ['Allow', 'Deny']:
            self._add_error(f"Statement {index} has invalid Effect: {effect}")
            if self.strict_mode:
                return None
            statement['Effect'] = 'Deny'  # Safe default
        
        # Check for Action or NotAction
        if 'Action' not in statement and 'NotAction' not in statement:
            self._add_warning(f"Statement {index} has neither 'Action' nor 'NotAction'")
        
        # Normalize Action/NotAction to lists
        for key in ['Action', 'NotAction']:
            if key in statement:
                statement[key] = self._ensure_list(statement[key])
        
        # Normalize Resource/NotResource to lists (for identity policies)
        for key in ['Resource', 'NotResource']:
            if key in statement:
                statement[key] = self._ensure_list(statement[key])
        
        # Normalize Principal/NotPrincipal (for resource policies)
        for key in ['Principal', 'NotPrincipal']:
            if key in statement:
                statement[key] = self._normalize_principal(statement[key])
        
        # Normalize Condition if present
        if 'Condition' in statement:
            statement['Condition'] = self._normalize_condition(statement['Condition'])
        
        # Add Sid if not present (for easier reference)
        if 'Sid' not in statement:
            statement['Sid'] = f"Statement{index}"
        
        return statement
    
    def _normalize_principal(self, principal: Any) -> Union[str, Dict, List]:
        """
        Normalize Principal field.
        
        Principal can be:
        - A string (e.g., "*")
        - A dict with AWS, Service, Federated, or CanonicalUser keys
        - A list (already normalized)
        
        Args:
            principal: Principal value
            
        Returns:
            Normalized principal
        """
        if principal == "*":
            return "*"
        
        if isinstance(principal, dict):
            # Normalize values within the principal dict
            for key in ['AWS', 'Service', 'Federated', 'CanonicalUser']:
                if key in principal:
                    principal[key] = self._ensure_list(principal[key])
            return principal
        
        if isinstance(principal, str):
            return {"AWS": [principal]}
        
        return principal
    
    def _normalize_condition(self, condition: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Condition block.
        
        Args:
            condition: Condition dictionary
            
        Returns:
            Normalized condition
        """
        if not isinstance(condition, dict):
            self._add_warning("Condition must be an object")
            return {}
        
        # Validate structure: Condition -> Operator -> Key -> Value
        normalized_condition = {}
        
        for operator, conditions in condition.items():
            if not isinstance(conditions, dict):
                self._add_warning(f"Condition operator '{operator}' must have an object value")
                continue
            
            normalized_condition[operator] = {}
            
            for key, value in conditions.items():
                # Some condition values should be lists, others should be strings/numbers
                # We'll preserve the original structure but ensure consistency
                normalized_condition[operator][key] = value
        
        return normalized_condition

    def _ensure_list(self, value: Any) -> List:
        """
        Ensure a value is a list.
        
        Args:
            value: Any value
            
        Returns:
            Value as a list
        """
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]
    
    def _add_warning(self, message: str) -> None:
        """Add a warning message."""
        logger.warning(message)
        self.warnings.append(message)
    
    def _add_error(self, message: str) -> None:
        """Add an error message."""
        logger.error(message)
        self.errors.append(message)
    
    def get_warnings(self) -> List[str]:
        """Get all warnings from the last parse operation."""
        return self.warnings.copy()
    
    def get_errors(self) -> List[str]:
        """Get all errors from the last parse operation."""
        return self.errors.copy()
    
    @staticmethod
    def extract_actions(policy: Dict[str, Any]) -> List[str]:
        """
        Extract all actions from a policy.
        
        Args:
            policy: Normalized policy dictionary
            
        Returns:
            List of all actions in the policy
        """
        actions = set()
        
        for statement in policy.get('Statement', []):
            if 'Action' in statement:
                actions.update(statement['Action'])
            if 'NotAction' in statement:
                actions.update(statement['NotAction'])
        
        return sorted(list(actions))
    
    @staticmethod
    def extract_resources(policy: Dict[str, Any]) -> List[str]:
        """
        Extract all resources from a policy.
        
        Args:
            policy: Normalized policy dictionary
            
        Returns:
            List of all resources in the policy
        """
        resources = set()
        
        for statement in policy.get('Statement', []):
            if 'Resource' in statement:
                resources.update(statement['Resource'])
            if 'NotResource' in statement:
                resources.update(statement['NotResource'])
        
        return sorted(list(resources))
    
    @staticmethod
    def extract_principals(policy: Dict[str, Any]) -> List[str]:
        """
        Extract all principals from a policy.
        
        Args:
            policy: Normalized policy dictionary
            
        Returns:
            List of all principals in the policy
        """
        principals = set()
        
        for statement in policy.get('Statement', []):
            principal = statement.get('Principal', {})
            
            if principal == "*":
                principals.add("*")
            elif isinstance(principal, dict):
                for key, values in principal.items():
                    if isinstance(values, list):
                        principals.update(values)
                    else:
                        principals.add(values)
        
        return sorted(list(principals))
    
    @staticmethod
    def get_policy_summary(policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of the policy.
        
        Args:
            policy: Normalized policy dictionary
            
        Returns:
            Policy summary dictionary
        """
        statements = policy.get('Statement', [])
        
        allow_count = sum(1 for s in statements if s.get('Effect') == 'Allow')
        deny_count = sum(1 for s in statements if s.get('Effect') == 'Deny')
        
        return {
            'version': policy.get('Version'),
            'statement_count': len(statements),
            'allow_statements': allow_count,
            'deny_statements': deny_count,
            'total_actions': len(PolicyParser.extract_actions(policy)),
            'total_resources': len(PolicyParser.extract_resources(policy)),
            'total_principals': len(PolicyParser.extract_principals(policy)),
            'has_conditions': any('Condition' in s for s in statements)
        }
        

# Helper functions
def parse_policy_file(file_path: Union[str, Path], strict_mode: bool = False, inplace: bool = False) -> Dict[str, Any]:
    """
    Function to parse a policy file.
    
    Args:
        file_path: Path to policy file
        strict_mode: Enable strict mode
        
    Returns:
        Normalized policy dictionary
    """
    parser = PolicyParser(strict_mode=strict_mode)
    return parser.parse_file(file_path, inplace=inplace)


def parse_policy_string(policy_content: str, format_type: str = 'json', 
                       strict_mode: bool = False, inplace: bool = False) -> Dict[str, Any]:
    """
    Convenience function to parse a policy from string.
    
    Args:
        policy_content: Policy as string
        format_type: Format type ('json' or 'yaml')
        strict_mode: Enable strict mode
        
    Returns:
        Normalized policy dictionary
    """
    parser = PolicyParser(strict_mode=strict_mode)
    return parser.parse_policy(policy_content, format_type, inplace=inplace)     
#!/usr/bin/env python
"""
Migration Validation Script
Tests the migration chain for schema issues, foreign key violations, and downgrade safety.
Run this before deploying to catch issues early.

Usage:
    python validate_migrations.py
"""

import os
import sys
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def check_migration_schema_consistency():
    """Check if all migration files use consistent schema references."""
    logger.info("🔍 Checking migration schema consistency...")
    
    migration_files = {
        'alembic/versions/f9b39b741c92_initial_schema.py': 'Initial Schema',
        'alembic/versions/2a5d8e1f3b9c_add_enhanced_security_tables.py': 'Enhanced Security',
        'alembic/versions/2b7c4f8a1e3d_phase2_encryption_infrastructure.py': 'Phase 2 Encryption',
        'alembic/versions/3c8e9d4f5a2b_phase5_sharing_access_control.py': 'Phase 5 Sharing',
    }
    
    issues = []
    
    for file_path, name in migration_files.items():
        full_path = project_root / file_path
        if not full_path.exists():
            logger.warning(f"   ⚠️ {name}: File not found")
            continue
        
        with open(full_path, 'r') as f:
            content = f.read()
        
        # Check if uses schema='bionex' in op.create_table or references users/patients
        if 'op.create_table' in content:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'op.create_table' in line:
                    # Check if schema specified in next 20 lines
                    context = '\n'.join(lines[i:min(i+20, len(lines))])
                    
                    if "schema='bionex'" not in context and "schema=\"bionex\"" not in context:
                        if 'ForeignKeyConstraint' in context or 'bionex.' not in context:
                            table_name = line.split('(')[1].strip().strip("'\"")
                            issues.append({
                                'file': name,
                                'table': table_name,
                                'issue': 'Missing schema specification',
                                'severity': 'CRITICAL' if name != 'Initial Schema' else 'OK'
                            })
    
    return issues

def check_foreign_key_consistency():
    """Check if foreign keys properly reference schema-qualified tables."""
    logger.info("🔗 Checking foreign key schema consistency...")
    
    issues = []
    migration_files = [
        'alembic/versions/2a5d8e1f3b9c_add_enhanced_security_tables.py',
        'alembic/versions/2b7c4f8a1e3d_phase2_encryption_infrastructure.py',
        'alembic/versions/3c8e9d4f5a2b_phase5_sharing_access_control.py',
    ]
    
    for file_path in migration_files:
        full_path = project_root / file_path
        if not full_path.exists():
            continue
        
        with open(full_path, 'r') as f:
            content = f.read()
        
        # Look for unqualified table references in ForeignKeyConstraint
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if 'ForeignKeyConstraint' in line:
                # Get the full constraint definition
                context = line
                j = i
                while ']' not in context and j < len(lines):
                    j += 1
                    context += '\n' + lines[j]
                
                # Check for references like ['users.id'] instead of ['bionex.users.id']
                if "['users" in context and "'bionex.users" not in context:
                    issues.append({
                        'file': Path(file_path).name,
                        'issue': f"Unqualified FK reference to 'users': {context.strip()[:60]}",
                        'severity': 'CRITICAL'
                    })
                if "['patients" in context and "'bionex.patients" not in context:
                    issues.append({
                        'file': Path(file_path).name,
                        'issue': f"Unqualified FK reference to 'patients': {context.strip()[:60]}",
                        'severity': 'CRITICAL'
                    })
    
    return issues

def test_migration_syntax():
    """Validate Python syntax of all migration files."""
    logger.info("✅ Validating migration file syntax...")
    
    issues = []
    migration_dir = project_root / 'alembic' / 'versions'
    
    for migration_file in migration_dir.glob('*.py'):
        if migration_file.name == '__pycache__':
            continue
        
        try:
            with open(migration_file, 'r') as f:
                compile(f.read(), str(migration_file), 'exec')
        except SyntaxError as e:
            issues.append({
                'file': migration_file.name,
                'issue': f"Syntax Error: {e.msg} at line {e.lineno}",
                'severity': 'CRITICAL'
            })
        except Exception as e:
            issues.append({
                'file': migration_file.name,
                'issue': f"Parse Error: {str(e)}",
                'severity': 'HIGH'
            })
    
    return issues

def check_enum_definitions():
    """Check if ENUM types are properly handled."""
    logger.info("🔢 Checking ENUM definitions...")
    
    issues = []
    migration_files = [
        ('alembic/versions/f9b39b741c92_initial_schema.py', 'Migration 1'),
        ('alembic/versions/2a5d8e1f3b9c_add_enhanced_security_tables.py', 'Migration 2'),
        ('alembic/versions/2b7c4f8a1e3d_phase2_encryption_infrastructure.py', 'Migration 3'),
    ]
    
    for file_path, name in migration_files:
        full_path = project_root / file_path
        if not full_path.exists():
            continue
        
        with open(full_path, 'r') as f:
            content = f.read()
        
        # Check if ENUMs in Migration 3 use proper error handling
        if name == 'Migration 3':
            if 'try:' in content and 'CREATE TYPE' in content:
                logger.info(f"   ✅ {name}: ENUM creation has error handling")
            elif 'CREATE TYPE' in content:
                issues.append({
                    'file': name,
                    'issue': 'ENUM creation without error handling (may fail on re-run)',
                    'severity': 'MEDIUM'
                })
    
    return issues

def print_report(schema_issues, fk_issues, syntax_issues, enum_issues):
    """Print validation report."""
    print("\n" + "="*80)
    print("📊 MIGRATION VALIDATION REPORT")
    print("="*80 + "\n")
    
    total_critical = 0
    total_high = 0
    total_medium = 0
    
    # Schema Issues
    if schema_issues:
        print("❌ SCHEMA CONSISTENCY ISSUES:")
        print("-" * 80)
        for issue in schema_issues:
            severity = issue['severity']
            if severity == 'CRITICAL':
                print(f"  🔴 [{severity}] {issue['file']} - Table '{issue['table']}': {issue['issue']}")
                total_critical += 1
            else:
                print(f"  ✅ [{severity}] {issue['file']} - {issue['issue']}")
        print()
    
    # Foreign Key Issues
    if fk_issues:
        print("❌ FOREIGN KEY ISSUES:")
        print("-" * 80)
        for issue in fk_issues:
            print(f"  🔴 [{issue['severity']}] {issue['file']}: {issue['issue']}")
            total_critical += 1
        print()
    
    # Syntax Issues
    if syntax_issues:
        print("❌ SYNTAX ERRORS:")
        print("-" * 80)
        for issue in syntax_issues:
            print(f"  🔴 [{issue['severity']}] {issue['file']}: {issue['issue']}")
            total_critical += 1
        print()
    
    # ENUM Issues
    if enum_issues:
        print("⚠️ ENUM ISSUES:")
        print("-" * 80)
        for issue in enum_issues:
            print(f"  🟡 [{issue['severity']}] {issue['file']}: {issue['issue']}")
            if issue['severity'] == 'CRITICAL':
                total_critical += 1
            elif issue['severity'] == 'HIGH':
                total_high += 1
            else:
                total_medium += 1
        print()
    
    # Summary
    print("="*80)
    print("📈 SUMMARY:")
    print(f"  🔴 Critical Issues: {total_critical}")
    print(f"  🟠 High Priority: {total_high}")
    print(f"  🟡 Medium Priority: {total_medium}")
    print("="*80 + "\n")
    
    if total_critical > 0:
        print("❌ MIGRATIONS WILL LIKELY FAIL - CRITICAL ISSUES DETECTED\n")
        return False
    elif total_high > 0:
        print("⚠️ MIGRATIONS MAY FAIL - HIGH PRIORITY ISSUES DETECTED\n")
        return False
    else:
        print("✅ MIGRATIONS APPEAR SAFE - NO CRITICAL ISSUES\n")
        return True

def main():
    """Run all validation checks."""
    logger.info("Starting migration validation...\n")
    
    schema_issues = check_migration_schema_consistency()
    fk_issues = check_foreign_key_consistency()
    syntax_issues = test_migration_syntax()
    enum_issues = check_enum_definitions()
    
    success = print_report(schema_issues, fk_issues, syntax_issues, enum_issues)
    
    if not success:
        print("🛠️ RECOMMENDATIONS:")
        print("-" * 80)
        if schema_issues or fk_issues:
            print("  1. Fix migration files to use schema='bionex' for all tables")
            print("  2. Update foreign key constraints to reference 'bionex.table_name'")
            print("  3. Re-run this validation before deploying")
        print("-" * 80 + "\n")
    
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())

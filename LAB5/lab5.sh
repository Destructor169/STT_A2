#!/bin/bash

# Lab 5: Code Coverage Analysis and Automated Test Case Generation
# Usage: ./lab5.sh [project_path] [module_name]

set -e

# Check if project path is provided
if [ -z "$1" ]; then
    echo "Usage: ./lab5.sh [project_path] [module_name]"
    echo "Example: ./lab5.sh /home/user/algorithms arrays.delete_nth"
    exit 1
fi

PROJECT_PATH=$1
MODULE_NAME=$2
VENV_NAME="venv_lab5"
REPORTS_DIR="lab5_reports"
GENERATED_TESTS_DIR="generated_tests"

# Create virtual environment
echo "Setting up virtual environment..."
python3 -m venv $VENV_NAME
source $VENV_NAME/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install pytest pytest-cov pytest-func-cov coverage pynguin

# Create directories
mkdir -p $REPORTS_DIR
mkdir -p $GENERATED_TESTS_DIR

# Function to run coverage analysis
run_coverage() {
    local suite_name=$1
    echo "Running coverage for test suite $suite_name..."
    
    coverage run -m pytest tests/
    coverage json -o $REPORTS_DIR/coverage_$suite_name.json
    coverage html -d $REPORTS_DIR/coverage_html_report_$suite_name
    coverage report
    
    echo "Coverage report for $suite_name generated at $REPORTS_DIR/coverage_html_report_$suite_name"
}

# Run coverage for original tests (Suite A)
run_coverage "A"

# Run Pynguin for automated test generation
if [ -n "$MODULE_NAME" ]; then
    echo "Running Pynguin for module $MODULE_NAME..."
    export PYNGUIN_DANGER_AWARE=1
    
    pynguin --project-path $PROJECT_PATH \
            --module-name algorithms.$MODULE_NAME \
            --output-path $GENERATED_TESTS_DIR \
            --algorithm DYNAMOSA \
            --maximum-search-time 300
            
    echo "Generated tests saved to $GENERATED_TESTS_DIR"
fi

# Run coverage for combined tests (Suite A + generated tests)
echo "Running combined coverage analysis..."
pytest tests/ $GENERATED_TESTS_DIR/ --cov=algorithms --cov-branch \
      --cov-report=xml:$REPORTS_DIR/coverage_combined.xml \
      --cov-report=html:$REPORTS_DIR/coverage_html_report_combined \
      --cov-report=term-missing

# Generate LCOV report
echo "Generating LCOV report..."
coverage lcov -o $REPORTS_DIR/coverage.lcov
genhtml $REPORTS_DIR/coverage.lcov --output-directory $REPORTS_DIR/lcov-report

echo "============================================"
echo "Lab 5 tasks completed successfully!"
echo "Reports generated in $REPORTS_DIR directory"
echo "Generated tests saved in $GENERATED_TESTS_DIR"
echo "============================================"

deactivate

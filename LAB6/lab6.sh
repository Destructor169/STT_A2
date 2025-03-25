#!/bin/bash

# Lab 6: Python Test Parallelization
# Usage: ./lab6.sh [num_runs]

set -e

NUM_RUNS=${1:-3}  # Default to 3 runs if not specified
RESULTS_DIR="lab6_results"
BENCHMARK_DIR="$RESULTS_DIR/benchmark"
PARALLEL_DIR="$RESULTS_DIR/parallel"
VENV_NAME="venv_lab6"

# Create directories
mkdir -p $BENCHMARK_DIR
mkdir -p $PARALLEL_DIR

# Setup virtual environment
echo "Setting up virtual environment..."
python3 -m venv $VENV_NAME
source $VENV_NAME/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install pytest pytest-xdist

# Function to get average real time from results
get_avg_time() {
    local pattern=$1
    local total=0
    local count=0
    
    for file in $pattern; do
        time_str=$(grep "real" $file | awk '{print $2}')
        time_sec=$(echo $time_str | awk -F'm|s' '{print $1 * 60 + $2}')
        total=$(echo "$total + $time_sec" | bc)
        count=$((count + 1))
    done
    
    if [ $count -gt 0 ]; then
        echo "scale=2; $total / $count" | bc
    else
        echo "0"
    fi
}

# Sequential benchmark
echo "Running sequential benchmark ($NUM_RUNS runs)..."
for i in $(seq 1 $NUM_RUNS); do
    echo "Run $i/$NUM_RUNS (sequential)"
    time pytest -v > $BENCHMARK_DIR/sequential_$i.txt 2>&1
done

# Process-level parallelization
echo "Running process-level parallelization tests..."
for workers in 1 auto; do
    for dist in load no; do
        echo "Testing $workers workers with $dist distribution..."
        for i in $(seq 1 $NUM_RUNS); do
            echo "Run $i/$NUM_RUNS (workers=$workers, dist=$dist)"
            time pytest -n $workers --dist $dist -v > \
                $PARALLEL_DIR/p_${workers}_${dist}_$i.txt 2>&1
        done
    done
done

# Thread-level parallelization (using pytest-parallel)
pip install pytest-parallel
echo "Running thread-level parallelization tests..."
for threads in 1 auto; do
    echo "Testing with $threads threads..."
    for i in $(seq 1 $NUM_RUNS); do
        echo "Run $i/$NUM_RUNS (threads=$threads)"
        time pytest --parallel-threads $threads -v > \
            $PARALLEL_DIR/t_${threads}_$i.txt 2>&1
    done
done

# Combined parallelization
echo "Running combined parallelization tests..."
for i in $(seq 1 $NUM_RUNS); do
    echo "Run $i/$NUM_RUNS (combined)"
    time pytest -n auto --dist load --parallel-threads auto -v > \
        $PARALLEL_DIR/combined_$i.txt 2>&1
done

# Generate summary report
echo "Generating performance summary..."
{
    echo "Test Configuration,Average Time (s)"
    echo "Sequential,$(get_avg_time "$BENCHMARK_DIR/sequential_*.txt")"
    echo "Process (1 worker, load),$(get_avg_time "$PARALLEL_DIR/p_1_load_*.txt")"
    echo "Process (auto workers, load),$(get_avg_time "$PARALLEL_DIR/p_auto_load_*.txt")"
    echo "Process (1 worker, no),$(get_avg_time "$PARALLEL_DIR/p_1_no_*.txt")"
    echo "Process (auto workers, no),$(get_avg_time "$PARALLEL_DIR/p_auto_no_*.txt")"
    echo "Thread (1 thread),$(get_avg_time "$PARALLEL_DIR/t_1_*.txt")"
    echo "Thread (auto threads),$(get_avg_time "$PARALLEL_DIR/t_auto_*.txt")"
    echo "Combined (auto workers + auto threads),$(get_avg_time "$PARALLEL_DIR/combined_*.txt")"
} > $RESULTS_DIR/performance_summary.csv

# Generate speedup comparison
echo "Generating speedup comparison..."
SEQ_TIME=$(get_avg_time "$BENCHMARK_DIR/sequential_*.txt")
{
    echo "Test Configuration,Time (s),Speedup (x)"
    echo "Sequential,$SEQ_TIME,1.00"
    
    for config in "Process (1 worker, load)" "Process (auto workers, load)" \
                  "Process (1 worker, no)" "Process (auto workers, no)" \
                  "Thread (1 thread)" "Thread (auto threads)" \
                  "Combined (auto workers + auto threads)"; do
        time=$(grep "^$config," $RESULTS_DIR/performance_summary.csv | cut -d',' -f2)
        speedup=$(echo "scale=2; $SEQ_TIME / $time" | bc)
        echo "$config,$time,$speedup"
    done
} > $RESULTS_DIR/speedup_comparison.csv

# Create visualization script
cat > $RESULTS_DIR/generate_plots.py << 'EOF'
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Load data
results_dir = os.path.dirname(os.path.abspath(__file__))
summary = pd.read_csv(os.path.join(results_dir, 'performance_summary.csv'))
speedup = pd.read_csv(os.path.join(results_dir, 'speedup_comparison.csv'))

# Plot performance comparison
plt.figure(figsize=(12, 6))
sns.barplot(x='Test Configuration', y='Average Time (s)', data=summary)
plt.title('Test Execution Time Comparison')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig(os.path.join(results_dir, 'execution_time_comparison.png'))
plt.close()

# Plot speedup comparison
plt.figure(figsize=(12, 6))
barplot = sns.barplot(x='Test Configuration', y='Speedup (x)', data=speedup)
plt.title('Speedup Compared to Sequential Execution')
plt.xticks(rotation=45, ha='right')
plt.axhline(1.0, color='red', linestyle='--')
plt.tight_layout()

# Add value labels
for p in barplot.patches:
    barplot.annotate(f"{p.get_height():.2f}x", 
                    (p.get_x() + p.get_width() / 2., p.get_height()),
                    ha='center', va='center', xytext=(0, 10),
                    textcoords='offset points')

plt.savefig(os.path.join(results_dir, 'speedup_comparison.png'))
plt.close()
EOF

# Generate visualizations
echo "Generating visualizations..."
python $RESULTS_DIR/generate_plots.py

echo "============================================"
echo "Lab 6 tasks completed successfully!"
echo "Results saved in $RESULTS_DIR directory"
echo "Performance summary: $RESULTS_DIR/performance_summary.csv"
echo "Speedup comparison: $RESULTS_DIR/speedup_comparison.csv"
echo "Visualizations: $RESULTS_DIR/*.png"
echo "============================================"

deactivate

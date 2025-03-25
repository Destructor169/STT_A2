import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
from collections import Counter


# Configuration
RESULTS_DIR = "vulnerability_analysis_results"
OUTPUT_DIR = "visualizations"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_data():
   """Load all CSV files from results directory"""
   data = {}
   for filename in os.listdir(RESULTS_DIR):
       if filename.endswith("_summary.csv"):
           repo_name = filename.replace("_summary.csv", "")
           df = pd.read_csv(os.path.join(RESULTS_DIR, filename))
           data[repo_name] = df
   return data


def plot_high_severity_trend(repo_name, df):
   """Plot high severity vulnerabilities over time"""
   plt.figure(figsize=(12, 6))
  
   # Ensure chronological order
   df = df.sort_values('Commit').reset_index(drop=True)
  
   # Plot with enhanced styling
   plt.plot(df.index, df['High Severity'],
            marker='o', linestyle='-', color='#e63946',
            linewidth=2, markersize=8, label='High Severity')
  
   # Add trend line
   if len(df) > 1:
       z = np.polyfit(df.index, df['High Severity'], 1)
       p = np.poly1d(z)
       plt.plot(df.index, p(df.index), "r--", linewidth=1.5, alpha=0.5)
  
   plt.title(f'{repo_name} - High Severity Vulnerabilities Over Time', pad=20, fontsize=14)
   plt.xlabel('Commit Sequence', labelpad=10)
   plt.ylabel('Number of Vulnerabilities', labelpad=10)
   plt.grid(True, linestyle='--', alpha=0.7)
   plt.xticks(rotation=45)
   plt.tight_layout()
  
   # Save plot
   output_path = os.path.join(OUTPUT_DIR, f'{repo_name}_high_severity_trend.png')
   plt.savefig(output_path, dpi=300, bbox_inches='tight')
   plt.close()
   print(f'Saved: {output_path}')


def plot_severity_distribution(repo_name, df):
   """Plot stacked severity distribution"""
   plt.figure(figsize=(14, 7))
  
   # Prepare data
   severity_df = df[['High Severity', 'Medium Severity', 'Low Severity']]
   severity_df = severity_df.rename(columns={
       'High Severity': 'High',
       'Medium Severity': 'Medium',
       'Low Severity': 'Low'
   })
  
   # Plot with better colors and styling
   ax = severity_df.plot(kind='bar', stacked=True, figsize=(14, 7),
                        color=['#e63946', '#ffbe0b', '#457b9d'],
                        width=0.9, alpha=0.9)
  
   plt.title(f'{repo_name} - Vulnerability Severity Distribution', pad=20, fontsize=14)
   plt.xlabel('Commit Sequence', labelpad=10)
   plt.ylabel('Number of Vulnerabilities', labelpad=10)
   plt.legend(title='Severity', bbox_to_anchor=(1.05, 1), loc='upper left')
   plt.grid(True, linestyle='--', alpha=0.3, axis='y')
   plt.xticks([])  # Hide commit hashes for clarity
   plt.tight_layout()
  
   # Add value labels for the total
   totals = severity_df.sum(axis=1)
   for i, total in enumerate(totals):
       if total > 0:  # Only label if there are vulnerabilities
           ax.text(i, total + 0.5, int(total),
                  ha='center', va='bottom', fontsize=8)
  
   # Save plot
   output_path = os.path.join(OUTPUT_DIR, f'{repo_name}_severity_distribution.png')
   plt.savefig(output_path, dpi=300, bbox_inches='tight')
   plt.close()
   print(f'Saved: {output_path}')


def plot_top_cwes(repo_name, df):
   """Plot top CWE categories"""
   # Extract and count CWEs
   cwe_list = []
   for cwe_str in df['Unique CWE IDs'].dropna():
       cwe_list.extend(cwe_str.split('; '))
  
   if not cwe_list:
       print(f"No CWE data found for {repo_name}")
       return
  
   cwe_counts = Counter(cwe_list)
   cwe_df = pd.DataFrame(cwe_counts.items(), columns=['CWE ID', 'Count']).sort_values('Count', ascending=False)
  
   # Get CWE descriptions (simplified for example)
   cwe_descriptions = {
       '79': 'XSS',
       '89': 'SQL Injection',
       '20': 'Input Validation',
       '78': 'OS Command Injection',
       '22': 'Path Traversal',
       '259': 'Hard-coded Password',
       '327': 'Weak Cryptography',
       '352': 'CSRF',
       '434': 'Unrestricted Upload',
       '502': 'Deserialization'
   }
  
   # Add descriptions to dataframe
   cwe_df['Description'] = cwe_df['CWE ID'].str.replace('CWE-', '').map(cwe_descriptions)
   cwe_df['Label'] = cwe_df['CWE ID'] + ': ' + cwe_df['Description']
  
   plt.figure(figsize=(14, 7))
  
   # Create horizontal bar plot for better readability
   ax = sns.barplot(x='Count', y='Label', data=cwe_df.head(10),
                   palette='viridis', orient='h')
  
   plt.title(f'{repo_name} - Top 10 CWE Categories', pad=20, fontsize=14)
   plt.xlabel('Occurrence Count', labelpad=10)
   plt.ylabel('CWE Category', labelpad=10)
  
   # Add value labels
   for p in ax.patches:
       width = p.get_width()
       ax.text(width + 0.5, p.get_y() + p.get_height()/2.,
               f'{int(width)}',
               ha='left', va='center', fontsize=10)
  
   plt.grid(True, linestyle='--', alpha=0.3, axis='x')
   plt.tight_layout()
  
   # Save plot
   output_path = os.path.join(OUTPUT_DIR, f'{repo_name}_top_cwes.png')
   plt.savefig(output_path, dpi=300, bbox_inches='tight')
   plt.close()
   print(f'Saved: {output_path}')


def plot_comparison_chart(all_data):
   """Plot comparison chart across all repositories"""
   # Prepare comparison data
   comparison_data = []
   for repo_name, df in all_data.items():
       summary = {
           'Repository': repo_name,
           'High': df['High Severity'].sum(),
           'Medium': df['Medium Severity'].sum(),
           'Low': df['Low Severity'].sum(),
           'Total': df[['High Severity', 'Medium Severity', 'Low Severity']].sum().sum()
       }
       comparison_data.append(summary)
  
   comparison_df = pd.DataFrame(comparison_data)
  
   # Create figure
   plt.figure(figsize=(14, 8))
  
   # Plot total vulnerabilities
   ax1 = plt.subplot(2, 1, 1)
   sns.barplot(x='Repository', y='Total', data=comparison_df,
               palette='rocket', alpha=0.8)
   plt.title('Total Vulnerabilities by Repository', pad=20, fontsize=14)
   plt.xlabel('')
   plt.ylabel('Total Vulnerabilities', labelpad=10)
  
   # Add value labels
   for p in ax1.patches:
       ax1.annotate(f"{int(p.get_height())}",
                   (p.get_x() + p.get_width() / 2., p.get_height()),
                   ha='center', va='center', xytext=(0, 10),
                   textcoords='offset points')
  
   # Plot severity breakdown
   plt.subplot(2, 1, 2)
   comparison_df.set_index('Repository')[['High', 'Medium', 'Low']].plot(
       kind='bar', stacked=True, color=['#e63946', '#ffbe0b', '#457b9d'],
       alpha=0.9, width=0.8)
   plt.title('Vulnerability Severity Breakdown', pad=20, fontsize=14)
   plt.xlabel('Repository', labelpad=10)
   plt.ylabel('Count', labelpad=10)
   plt.legend(title='Severity', bbox_to_anchor=(1.05, 1), loc='upper left')
  
   plt.tight_layout()
  
   # Save plot
   output_path = os.path.join(OUTPUT_DIR, 'repository_comparison.png')
   plt.savefig(output_path, dpi=300, bbox_inches='tight')
   plt.close()
   print(f'Saved: {output_path}')


def main():
   """Main function to generate all visualizations"""
   print("Loading data...")
   data = load_data()
  
   if not data:
       print("No CSV files found in the results directory!")
       return
  
   print("\nGenerating visualizations...")
   for repo_name, df in data.items():
       print(f"\nProcessing {repo_name}...")
       plot_high_severity_trend(repo_name, df)
       plot_severity_distribution(repo_name, df)
       plot_top_cwes(repo_name, df)
  
   # Generate comparison chart
   plot_comparison_chart(data)
  
   print("\nAll visualizations generated successfully!")
   print(f"Check the '{OUTPUT_DIR}' directory for your graphs.")


if __name__ == "__main__":
   import numpy as np  # Required for trend line calculation
   main()

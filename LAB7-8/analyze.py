import os
import json
import subprocess
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns


# Configuration
REPOSITORIES = [
   {"name": "music-dl", "url": "https://github.com/0xhjk/music-dl"},
   {"name": "ChatTTS", "url": "https://github.com/2noise/ChatTTS"},
   {"name": "llama-cpp-python", "url": "https://github.com/abetlen/llama-cpp-python"}
]
COMMITS_TO_ANALYZE = 100
OUTPUT_DIR = "vulnerability_analysis_results"


def setup_environment():
   """Create output directory and virtual environment"""
   os.makedirs(OUTPUT_DIR, exist_ok=True)
  
   if not os.path.exists("bandit_venv"):
       print("Creating virtual environment...")
       subprocess.run(["python3", "-m", "venv", "bandit_venv"], check=True)
       subprocess.run(["bandit_venv/bin/pip", "install", "bandit", "pandas", "matplotlib", "seaborn"], check=True)


def clone_repositories():
   """Clone all repositories if they don't exist"""
   for repo in REPOSITORIES:
       if not os.path.exists(repo["name"]):
           print(f"Cloning {repo['name']}...")
           subprocess.run(["git", "clone", repo["url"]], check=True)


def generate_commit_lists():
   """Generate commit lists for each repository"""
   for repo in REPOSITORIES:
       print(f"Generating commit list for {repo['name']}...")
       os.chdir(repo["name"])
      
       # Fixed: Use proper file handling instead of shell redirection
       with open("commit_list.txt", "w") as f:
           subprocess.run(["git", "log", "--pretty=format:%H", "--no-merges", "-n", str(COMMITS_TO_ANALYZE)],
                         stdout=f, check=True)
      
       os.chdir("..")


def run_bandit_analysis():
   """Run Bandit on each commit for all repositories"""
   for repo in REPOSITORIES:
       print(f"\nAnalyzing {repo['name']} with Bandit...")
       os.chdir(repo["name"])
      
       # Read commits
       with open("commit_list.txt") as f:
           commits = f.read().splitlines()
      
       # Process each commit
       for commit in commits:
           output_file = f"bandit_results_{commit}.json"
           if os.path.exists(output_file):
               continue
              
           try:
               subprocess.run(["git", "checkout", commit], check=True)
               subprocess.run(["../bandit_venv/bin/bandit", "-r", ".", "-f", "json", "-o", output_file], check=True)
           except subprocess.CalledProcessError as e:
               print(f"Error analyzing commit {commit[:8]}...: {e}")
      
       os.chdir("..")


def analyze_results():
   """Analyze Bandit results and generate visualizations"""
   all_results = []
  
   for repo in REPOSITORIES:
       print(f"\nProcessing results for {repo['name']}...")
       os.chdir(repo["name"])
      
       # Process all JSON files
       repo_results = []
       for filename in os.listdir('.'):
           if filename.startswith('bandit_results_') and filename.endswith('.json'):
               with open(filename) as f:
                   data = json.load(f)
              
               results = data.get("results", [])
               confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
               severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
               unique_cwes = set()


               for issue in results:
                   confidence = issue.get("issue_confidence", "UNKNOWN")
                   if confidence in confidence_counts:
                       confidence_counts[confidence] += 1


                   severity = issue.get("issue_severity", "UNKNOWN")
                   if severity in severity_counts:
                       severity_counts[severity] += 1


                   cwe_data = issue.get("issue_cwe", {})
                   if isinstance(cwe_data, dict):
                       cwe_id = cwe_data.get("id")
                       if cwe_id:
                           unique_cwes.add(str(cwe_id))


               commit_hash = filename.replace("bandit_results_", "").replace(".json", "")
               repo_results.append({
                   "Repository": repo["name"],
                   "Commit": commit_hash,
                   "High Severity": severity_counts["HIGH"],
                   "Medium Severity": severity_counts["MEDIUM"],
                   "Low Severity": severity_counts["LOW"],
                   "Unique CWE IDs": "; ".join(sorted(unique_cwes)) if unique_cwes else ""
               })
      
       # Save repository-specific results
       repo_df = pd.DataFrame(repo_results)
       repo_df.to_csv(f"../{OUTPUT_DIR}/{repo['name']}_summary.csv", index=False)
      
       # Generate visualizations
       generate_visualizations(repo["name"], repo_df)
      
       all_results.extend(repo_results)
       os.chdir("..")
  
   # Save combined results
   combined_df = pd.DataFrame(all_results)
   combined_df.to_csv(f"{OUTPUT_DIR}/combined_summary.csv", index=False)
   print(f"\nAll results saved to {OUTPUT_DIR}/ directory")


def generate_visualizations(repo_name, df):
   """Generate all visualizations for a repository"""
   # Create repository-specific output directory
   repo_output_dir = f"{OUTPUT_DIR}/{repo_name}"
   os.makedirs(repo_output_dir, exist_ok=True)
  
   # RQ1: High severity over time
   df_filtered = df[df["High Severity"] > 0][["Commit", "High Severity"]]
   df_filtered["Commit_Index"] = range(1, len(df_filtered) + 1)
  
   plt.figure(figsize=(10, 5))
   plt.plot(df_filtered["Commit_Index"], df_filtered["High Severity"], marker='o', linestyle='-')
   plt.xlabel("Commits (Chronological Order)")
   plt.ylabel("Number of High Severity Issues")
   plt.title(f"{repo_name} - High Severity Vulnerabilities Over Time")
   plt.grid()
   plt.savefig(f"{repo_output_dir}/RQ1_plot.png", dpi=300, bbox_inches="tight")
   plt.close()
  
   # RQ2: Stacked severity comparison
   severity_df = df[["Commit", "High Severity", "Medium Severity", "Low Severity"]]
   severity_df.set_index("Commit", inplace=True)
  
   severity_df.plot(kind="bar", stacked=True, figsize=(12, 6), colormap="coolwarm")
   plt.xlabel("Commits (Chronological Order)")
   plt.ylabel("Number of Vulnerabilities")
   plt.title(f"{repo_name} - Vulnerability Severity Distribution")
   plt.legend(title="Severity")
   plt.xticks([])
   plt.grid()
   plt.savefig(f"{repo_output_dir}/RQ2_plot.png", dpi=300, bbox_inches="tight")
   plt.close()
  
   # RQ3: Top CWEs
   cwe_list = []
   for cwe_str in df["Unique CWE IDs"]:
       if pd.notna(cwe_str):
           cwe_list.extend(cwe_str.split("; "))
  
   if cwe_list:
       cwe_counts = Counter(cwe_list)
       cwe_df = pd.DataFrame(cwe_counts.items(), columns=["CWE ID", "Count"]).sort_values(by="Count", ascending=False)
      
       plt.figure(figsize=(12, 5))
       sns.barplot(x="CWE ID", y="Count", data=cwe_df.head(10), palette="viridis")
       plt.xlabel("CWE ID")
       plt.ylabel("Occurrence Count")
       plt.title(f"{repo_name} - Top 10 CWE Categories")
       plt.xticks(rotation=45)
       plt.grid()
       plt.savefig(f"{repo_output_dir}/RQ3_plot.png", dpi=300, bbox_inches="tight")
       plt.close()


if __name__ == "__main__":
   print("Starting vulnerability analysis for all repositories...")
   setup_environment()
   clone_repositories()
   generate_commit_lists()
   run_bandit_analysis()
   analyze_results()
   print("\nAnalysis complete! Check the 'vulnerability_analysis_results' directory for outputs.")

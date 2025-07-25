# cve.icu

[CVE.ICU](https://cve.icu) is a passion project by [Jerry Gamblin](https://www.jerrygamblin.com). The goal is to dive deep into Common Vulnerabilities and Exposures (CVE) by pulling and analyzing all the CVE data from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/).

## Goals
The main aim of CVE.ICU is to make sense of all this data and present it in a way that's easy to understand through cool graphs and charts.  
This automated analysis helps:
- Spot patterns and trends in cybersecurity vulnerabilities.
- Give researchers and cybersecurity pros a better handle on what's going on and what's coming next.

## Open Source and Collaboration
The [source code](https://github.com/jgamblin/cve.icu) for this project is up on GitHub. It's open for everyone to see, use, and improve. By keeping it open-source, I'm hoping to get contributions and ideas from the community to make it even better.

## Timely Updates
To keep things fresh, the data on CVE.ICU is updated every 4 hours using GitHub Actions. This way, you always get the latest insights into the ever-changing world of cybersecurity vulnerabilities.

## Get Involved
I love hearing from people who are interested in this project. Feel free to reach out to me on Twitter [@jgamblin](https://twitter.com/jgamblin) if you have any questions or just want to chat about CVE.ICU. If you're interested in contributing, check out the [GitHub repository](https://github.com/jgamblin/cve.icu).

## How to Use
1. **Clone the repository**:
    ```sh
    git clone https://github.com/jgamblin/cve.icu.git
    cd cve.icu
    ```

2. **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

3. **Run Jupyter Book**:
    ```sh
    jupyter-book build .
    ```

4. **View the book**:
    Open the generated HTML files in your browser to explore the data and visualizations.

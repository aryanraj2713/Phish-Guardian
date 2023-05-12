# PhishGuardian
### - Working for a Safer Internet
### https://kzilla.xyz/phishguardian
PhishGuardian aims to detect whether a URL is safe or not using a decision tree algorithm. The project uses a web app to interact with users, and a Python backend to process the user input and make predictions about the safety of a given URL.
The decision tree algorithm is a machine learning technique that uses a series of binary decisions to classify input data into categories. In the case of PhishGuardian, the algorithm analyzes the characteristics of a URL and decides whether it is safe or not based on a set of pre-defined rules. The algorithm is trained on a dataset of known safe and phishing URLs, so it can accurately classify new URLs that it hasn't seen before. The web app allows users to input a URL and receive a prediction about its safety. The user interface is designed to be user-friendly and intuitive, with clear instructions on how to use the app. Once the user inputs a URL, the app sends the URL to the Python backend, which runs the decision tree algorithm and returns a prediction about the safety of the URL. The prediction is then displayed to the user in the web app.
The Python backend is responsible for processing the user input, running the decision tree algorithm, and returning the prediction to the web app. The backend is written in Python, which is a popular language for machine learning and data analysis. The backend is also responsible for training the decision tree algorithm on a dataset of known safe and phishing URLs, so it can make accurate predictions.

## Files for reference -
* [Presentation ](https://www.canva.com/design/DAFdktmiEKU/8EIVJAiIAeuemGgWoWZFkg/edit?utm_content=DAFdktmiEKU&utm_campaign=designshare&utm_medium=link2&utm_source=sharebutton)
* [Demo Vedio](https://drive.google.com/file/d/1jbHC00ibsEOs0XNXANm4zM7d0XBtqDpv/view?usp=share_link)

## Running the web-application locally
```
git clone https://github.com/aryanraj2713/Phish-Guardian.git
cd Phish-Guardian
```
* Make sure Chrome Browser or web-driver version 89.0.4356.6 ,or later version is available.
```
pip install -r requirements.txt
python3 main.py 
```


## Screenshot 
### Landing Page 
![Landing Page](https://user-images.githubusercontent.com/75358720/226133661-ee11bb1d-2c8e-4891-902b-5cebbd40e1f8.png)


### Results Page 
![Result Page](https://user-images.githubusercontent.com/90250628/226135496-10a0ca52-8f2b-4a84-a01e-d69645dc7b05.jpg)


## Technologies Used -
* Flask
* Sk-Learn
* HTML and CSS
* Selenium
* Git

## Data-set credits -

```
@misc{Dua:2019 ,
author = "Dua, Dheeru and Graff, Casey",
year = "2017",
title = "{UCI} Machine Learning Repository",
url = "http://archive.ics.uci.edu/ml",
institution = "University of California, Irvine, School of Information and Computer Sciences" }

Dua, D. and Graff, C. (2019). UCI Machine Learning Repository [http://archive.ics.uci.edu/ml]. Irvine, CA: University of California, School of Information and Computer Science.


```
## Reference research papers -


* Mohammad, Rami, McCluskey, T.L. and Thabtah, Fadi (2012) An Assessment of Features Related to Phishing Websites using an Automated Technique. In: International Conferece For Internet Technology And Secured Transactions. ICITST 2012 . IEEE, London, UK, pp. 492-497. ISBN 978-1-4673-5325-0

* Mohammad, Rami, Thabtah, Fadi Abdeljaber and McCluskey, T.L. (2014) Predicting phishing websites based on self-structuring neural network. Neural Computing and Applications, 25 (2). pp. 443-458. ISSN 0941-0643

* Mohammad, Rami, McCluskey, T.L. and Thabtah, Fadi Abdeljaber (2014) Intelligent Rule based Phishing Websites Classification. IET Information Security, 8 (3). pp. 153-160. ISSN 1751-8709


<div><h2><strong>Developers of this Repository -</strong></h2></div>

<table align="center">
<tr align="center">
<td>

**Puranjay Bhargava**

<p align="center">
<img src = "https://avatars.githubusercontent.com/u/90250628?s=400&u=59a21a80b8390e1aaefed3038d5f87745e4caf55&v=4"  height="120" alt="Puranjay Bhargava">
</p>
<p align="center">
<a href = "https://github.com/puranjayb"><img src = "http://www.iconninja.com/files/241/825/211/round-collaboration-social-github-code-circle-network-icon.svg" width="36" height = "36"/></a>
<a href = "https://www.linkedin.com/in/puranjayb/">
<img src = "http://www.iconninja.com/files/863/607/751/network-linkedin-social-connection-circular-circle-media-icon.svg" width="36" height="36"/>
</a>
</p>
</td>

<td>

**Aryan Raj**

<p align="center">
<img src = "https://avatars.githubusercontent.com/u/75358720?v=4"  height="120" alt="Aryan Raj">
</p>
<p align="center">
<a href = "https://github.com/aryanraj2713"><img src = "http://www.iconninja.com/files/241/825/211/round-collaboration-social-github-code-circle-network-icon.svg" width="36" height = "36"/></a>
<a href = "https://www.linkedin.com/in/aryan-raj-3a68b39a/">
<img src = "http://www.iconninja.com/files/863/607/751/network-linkedin-social-connection-circular-circle-media-icon.svg" width="36" height="36"/>
</a>
</p>
</td>

<td>

**Aakash**

<p align="center">
<img src = "https://avatars.githubusercontent.com/u/93485049?v=4"  height="120" alt="Aakash">
</p>
<p align="center">
  
<a href = "https://github.com/Aakash-sittu"><img src = "http://www.iconninja.com/files/241/825/211/round-collaboration-social-github-code-circle-network-icon.svg" width="36" height = "36"/></a>
<a href = "https://www.linkedin.com/in/aakash-sittu/">
<img src = "http://www.iconninja.com/files/863/607/751/network-linkedin-social-connection-circular-circle-media-icon.svg" width="36" height="36"/>
</a>
</p>
</td>

</table>


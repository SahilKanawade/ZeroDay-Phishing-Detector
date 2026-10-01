\# Zero-Day Phishing Detector



\### An Explainable Hybrid AI Framework for Real-Time Zero-Day Phishing Website Detection Using Multi-Modal Feature Analysis



\## Overview



Zero-Day Phishing Detector is a cybersecurity research project designed to detect potentially malicious and phishing websites using multiple layers of analysis.



The system combines URL analysis, domain and DNS analysis, webpage and HTML analysis, machine learning, threat intelligence heuristics, hybrid risk scoring, and Explainable AI (XAI).



The goal is to provide real-time phishing detection along with understandable reasons behind the security assessment.



\## Key Features



\* URL structure and feature analysis

\* Domain and DNS analysis

\* Webpage and HTML analysis

\* Machine Learning-based phishing classification

\* Random Forest phishing detection model

\* Threat intelligence heuristic analysis

\* Hybrid risk scoring from 0–100

\* Explainable AI (XAI)

\* Machine-learning feature importance

\* Real-time FastAPI backend

\* React-based security dashboard

\* Browser extension architecture

\* API health monitoring

\* Vercel frontend deployment support

\* Render backend deployment support



\## System Architecture



```text

&#x20;                        User

&#x20;                          |

&#x20;                          v

&#x20;                   Vercel Frontend

&#x20;                   React + Vite

&#x20;                          |

&#x20;                          | HTTPS API Request

&#x20;                          v

&#x20;                   Render Backend

&#x20;                   FastAPI + Python

&#x20;                          |

&#x20;         +----------------+----------------+

&#x20;         |                |                |

&#x20;         v                v                v

&#x20;    URL Analysis    Domain / DNS      HTML Analysis

&#x20;         |                |                |

&#x20;         +----------------+----------------+

&#x20;                          |

&#x20;                          v

&#x20;                 Threat Intelligence

&#x20;                          |

&#x20;                          v

&#x20;                 Machine Learning

&#x20;                          |

&#x20;                          v

&#x20;                  Explainable AI

&#x20;                          |

&#x20;                          v

&#x20;                 Hybrid Risk Engine

&#x20;                          |

&#x20;                          v

&#x20;                 Security Assessment

```



\## How It Works



The user submits a website URL through the React dashboard.



The backend then performs multiple analysis stages:



1\. URL feature extraction

2\. Domain and DNS analysis

3\. Webpage and HTML analysis

4\. Threat intelligence heuristic analysis

5\. Machine learning prediction

6\. Explainable AI analysis

7\. Hybrid risk scoring



The results are combined and presented through the web dashboard.



\## Machine Learning



The project uses a \*\*Random Forest Classifier\*\* trained using the \*\*UCI Phishing Websites Dataset\*\*.



The model uses 30 features related to URL characteristics, domain information, webpage indicators, and phishing-related attributes.



The trained model is stored at:



```text

ml/models/phishing\_model.pkl

```



\### Dataset



UCI Phishing Websites Dataset:



https://archive.ics.uci.edu/dataset/327/phishing



\## Analysis Layers



\### 1. URL Analysis



The system analyzes characteristics such as:



\* URL length

\* Hostname length

\* Number of dots

\* Number of hyphens

\* Number of slashes

\* HTTPS usage

\* Suspicious keywords

\* IP address usage

\* URL shortening

\* Subdomain indicators

\* Suspicious URL patterns



\### 2. Domain and DNS Analysis



The system checks:



\* Domain availability

\* DNS resolution

\* DNS records

\* Resolved IP addresses



\### 3. Webpage and HTML Analysis



The system analyzes accessible webpages for indicators such as:



\* HTML forms

\* Password fields

\* External form actions

\* External links

\* Iframes

\* Suspicious JavaScript behavior

\* Hidden elements

\* External resources

\* Popup-related behavior



\### 4. Threat Intelligence



The current threat-intelligence layer uses local heuristic indicators including:



\* Suspicious keywords

\* Suspicious URL patterns

\* Suspicious TLD indicators



External reputation services are not currently integrated.



\### 5. Hybrid Risk Engine



The different analysis layers are combined to generate a risk score from 0 to 100.



```text

0 ------------------------------ 100

Low             Medium            High

```



The risk score represents a security assessment and should not be treated as absolute certainty.



\### 6. Explainable AI



The system provides explanations including:



\* Observed suspicious indicators

\* Positive security indicators

\* Machine-learning prediction

\* Feature importance

\* Threat-intelligence findings

\* Analysis limitations



This helps users understand why a URL received its assessment.



\## Technology Stack



\### Frontend



\* React

\* Vite

\* JavaScript

\* CSS



\### Backend



\* Python

\* FastAPI

\* Uvicorn

\* Requests

\* BeautifulSoup



\### Machine Learning



\* Scikit-learn

\* Pandas

\* NumPy

\* Random Forest

\* Feature Engineering

\* Hybrid Risk Scoring

\* Explainable AI



\## Project Structure



```text

ZeroDay-Phishing-Detector/

│

├── backend/

│   └── app/

│       ├── main.py

│       ├── url\_analyzer.py

│       ├── domain\_analyzer.py

│       ├── html\_analyzer.py

│       ├── threat\_intelligence.py

│       ├── feature\_fusion.py

│       ├── risk\_engine.py

│       └── explainability.py

│

├── frontend/

│   ├── src/

│   │   ├── App.jsx

│   │   ├── index.css

│   │   └── main.jsx

│   ├── package.json

│   └── index.html

│

├── ml/

│   ├── dataset/

│   ├── preprocessing/

│   ├── training/

│   ├── models/

│   │   └── phishing\_model.pkl

│   └── evaluation/

│

├── datasets/

├── docs/

├── extension/

│

├── .gitignore

├── LICENSE

└── README.md

```



\## Local Installation



\### 1. Clone the Repository



```bash

git clone https://github.com/YOUR-USERNAME/ZeroDay-Phishing-Detector.git

cd ZeroDay-Phishing-Detector

```



\### 2. Backend Setup



Create a Python virtual environment:



```powershell

python -m venv venv

```



Activate the environment:



```powershell

.\\venv\\Scripts\\Activate.ps1

```



Install the backend dependencies:



```powershell

pip install -r backend/requirements.txt

```



\### 3. Start the Backend



From the project root:



```powershell

python -m uvicorn backend.app.main:app --reload

```



The backend will normally be available at:



```text

http://127.0.0.1:8000

```



FastAPI Swagger documentation:



```text

http://127.0.0.1:8000/docs

```



Health endpoint:



```text

http://127.0.0.1:8000/health

```



\### 4. Frontend Setup



Open another terminal:



```powershell

cd frontend

npm install

```



Start the development server:



```powershell

npm run dev

```



The frontend will normally be available at:



```text

http://localhost:5173

```



\## Environment Configuration



The frontend uses an environment variable to connect to the backend.



Create:



```text

frontend/.env

```



For local development:



```env

VITE\_API\_URL=http://127.0.0.1:8000

```



For production deployment, the value should be replaced with the deployed Render backend URL.



Do not commit private secrets or environment files containing sensitive information.



\## Deployment



The project is designed as a two-part deployment:



```text

Frontend  →  Vercel

Backend   →  Render

```



\### Frontend — Vercel



The React/Vite frontend can be deployed to Vercel.



The Vercel environment variable should be configured as:



```text

VITE\_API\_URL=<YOUR-RENDER-BACKEND-URL>

```



Example:



```text

VITE\_API\_URL=https://your-backend.onrender.com

```



\### Backend — Render



The FastAPI backend can be deployed as a Render web service.



The backend should be configured to run with Uvicorn.



Example production start command:



```text

uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT

```



The final Render URL will be used by the Vercel frontend through the `VITE\_API\_URL` environment variable.



\### Deployment Architecture



```text

&#x20;                 Internet User

&#x20;                      |

&#x20;                      v

&#x20;            Vercel React Frontend

&#x20;                      |

&#x20;                HTTPS Request

&#x20;                      |

&#x20;                      v

&#x20;            Render FastAPI Backend

&#x20;                      |

&#x20;         +------------+------------+

&#x20;         |            |            |

&#x20;         v            v            v

&#x20;      URL/DNS      HTML       ML Model

&#x20;      Analysis    Analysis    Prediction

&#x20;         |            |            |

&#x20;         +------------+------------+

&#x20;                      |

&#x20;                      v

&#x20;               Risk Assessment

&#x20;                      |

&#x20;                      v

&#x20;                 JSON Response

&#x20;                      |

&#x20;                      v

&#x20;            Vercel Dashboard

```



\## Security Considerations



The webpage analyzer performs server-side requests to URLs submitted for analysis.



Before using the application as a public production service, additional security controls should be implemented, including:



\* SSRF protection

\* Blocking private and loopback IP addresses

\* Redirect validation

\* Response-size limits

\* Maximum redirect limits

\* Request timeouts

\* Rate limiting

\* Input validation

\* Logging and monitoring



The application should not be treated as a guarantee that a website is safe or malicious.



\## Limitations



\* Machine-learning predictions depend on the training dataset and selected features.

\* The current threat-intelligence layer is heuristic-based.

\* Some websites may block automated requests.

\* JavaScript-heavy websites may not be fully represented by static HTML analysis.

\* External reputation APIs are not currently integrated.

\* Risk scores are security assessments and should not be interpreted as absolute certainty.

\* Detection performance may vary for previously unseen phishing techniques.



\## Future Development



\* Browser extension integration

\* Real-time external threat intelligence

\* Additional machine-learning models

\* Improved zero-day detection

\* Advanced JavaScript analysis

\* Dynamic webpage analysis

\* Model calibration

\* Continuous model evaluation

\* Production security hardening

\* Security monitoring and rate limiting

\* Automated threat intelligence integration



\## Project Goals



The project aims to improve phishing detection by combining:



```text

URL Features

&#x20;    +

Domain Intelligence

&#x20;    +

Webpage Analysis

&#x20;    +

Threat Indicators

&#x20;    +

Machine Learning

&#x20;    +

Explainable AI

&#x20;    =

Hybrid Phishing Risk Assessment

```



The primary goals are:



1\. Detect potentially malicious phishing URLs.

2\. Improve detection of previously unseen phishing websites.

3\. Reduce dependence on blacklist-only detection.

4\. Provide understandable explanations for security assessments.

5\. Build a foundation for real-time browser-based phishing protection.



\## Responsible Use



This project is intended for:



\* Cybersecurity education

\* Academic research

\* Defensive security analysis

\* Authorized security testing



Do not use this project to access, disrupt, or interact with websites without appropriate authorization.



\## Author



\*\*Sahil Kanawade\*\*



Cybersecurity Student



\## License



Copyright © 2026 Sahil Kanawade.



All Rights Reserved.



See the `LICENSE` file for details.




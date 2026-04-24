# SQLIA-Detection
# 🛡️ SQL Injection Detection System 

## 📌 Overview

This project presents a **Machine Learning-based SQL Injection Detection System** designed to identify and block malicious SQL queries in real time.
It combines **statistical learning techniques** with **rule-based heuristics** to improve detection accuracy and reliability.

The system is built with a modular architecture and supports both **command-line execution** and an **interactive GUI interface**.

---

## 🚀 Key Features

* **ML-Based Detection Engine**
  Utilizes TF-IDF vectorization, dimensionality reduction, and a Random Forest classifier to detect malicious queries.

* **Hybrid Security Approach**
  Combines machine learning with heuristic pattern detection for improved robustness.

* **Real-Time Query Processing**
  Intercepts and analyzes SQL queries before execution.

* **Interactive GUI Support**
  Provides a user-friendly interface for testing queries.

* **Logging & Monitoring**
  Records all processed queries with timestamps for auditing and analysis.

* **Modular Design**
  Clean separation of components for scalability and maintainability.

---

## 🏗️ System Architecture

```
User Input
   ↓
Interceptor (captures query)
   ↓
Detection Engine (ML + Heuristics)
   ↓
Handler (Decision: ALLOWED / BLOCKED)
   ↓
Logger (Stores query & result)
```

---

## 🧠 Detection Methodology

The system employs a **hybrid detection strategy**:

### 1. Machine Learning

* TF-IDF Vectorization (n-grams)
* Truncated SVD for dimensionality reduction
* Random Forest Classifier
* Probability-based classification with thresholding

### 2. Heuristic Analysis

* Detects suspicious SQL patterns such as:

  * `' OR 1=1`
  * `--`, `;`, `#`, comments
  * Injection-specific keywords

This combination ensures detection of both **known and unknown attack patterns**.

---

## 🧪 Example

| Input Query              | Output  |
| ------------------------ | ------- |
| `' OR 1=1 --`            | BLOCKED |
| `SELECT name FROM users` | ALLOWED |
| `DROP TABLE students;`   | BLOCKED |

---

## 🛠️ Tech Stack

* **Language:** Python
* **Libraries:**

  * scikit-learn
  * pandas, numpy
  * joblib
* **GUI:** Tkinter

---

## 📂 Project Structure

```
├── app.py              # Main execution (CLI testing)
├── detector.py         # ML model & detection logic
├── interceptor.py      # Query interception
├── handler.py          # Decision handling
├── logger.py           # Logging system
├── gui_app.py          # GUI application
├── data/
│   ├── model.pkl       # Trained ML model
│   └── query_log.txt   # Logs
```

---

## ▶️ Getting Started

### 1. Clone the Repository

```
git clone <your-repo-link>
cd <your-project-folder>
```

### 2. Install Dependencies

```
pip install -r requirements.txt
```

### 3. Run the Application

**CLI Version**

```
python app.py
```

**GUI Version**

```
python gui_app.py
```

---

## 📊 Model Performance

The model is evaluated using:

* Accuracy Score
* ROC-AUC Score
* Confusion Matrix

Performance metrics are displayed during training.

---

## 🔐 Use Cases

* Web Application Security
* Database Query Validation
* API Input Filtering
* Educational Demonstration of SQL Injection Prevention

---

## 💡 Future Enhancements

* Integration with live web frameworks (Flask/Django)
* REST API for real-time deployment
* Deep learning models (LSTM/BERT)
* Dashboard for monitoring and analytics

---

## 📄 License

This project is developed for educational and demonstration purposes.

---

## 👤 Author

Samarpreet Singh

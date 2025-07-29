## SMPP PDU Chain Visualizer

### Usage

1. **Input PCAP Directory**:

   - Enter the directory path containing your PCAP files in the first input box. If no directory is provided, the project will default to using PCAP files from the project root directory.

2. **Generate CSV**:

   - Click **Generate CSV**. The code parses all PCAP files in the selected directory and saves the extracted SMPP PDU data into CSV files for easy searching and analysis.

3. **Download CSV**:

   - Click **Download Full Chain CSV** to download the complete CSV containing all message chains.

4. **Search by Criteria**:

   - In the search bar you can now enter one or more comma-separated values for any of these fields:
     - **message_id** (Telco ID)
     - **submit_src** (source IP:port)
     - **submit_dst** (destination IP:port)
   - The results table will display only the chains matching any of the entered values.

#### Table Columns Explained

| Column Name          | Description                                    |
| -------------------- | ---------------------------------------------- |
| `message_id`         | Unique ID assigned to the message by the telco |
| `submit_sm_seq`      | Sequence number of the `submit_sm` PDU         |
| `submit_time`        | Timestamp when `submit_sm` was sent            |
| `submit_src`         | Source IP and port of `submit_sm`              |
| `submit_dst`         | Destination IP and port of `submit_sm`         |
| `submit_resp_time`   | Timestamp when `submit_sm_resp` was received   |
| `submit_resp_src`    | Source IP and port of `submit_sm_resp`         |
| `submit_resp_dst`    | Destination IP and port of `submit_sm_resp`    |
| `deliver_seq`        | Sequence number of the `deliver_sm` PDU        |
| `deliver_time`       | Timestamp when `deliver_sm` was sent           |
| `deliver_src`        | Source IP and port of `deliver_sm`             |
| `deliver_dst`        | Destination IP and port of `deliver_sm`        |
| `deliver_resp_time`  | Timestamp when `deliver_sm_resp` was received  |
| `deliver_resp_src`   | Source IP and port of `deliver_sm_resp`        |
| `deliver_resp_dst`   | Destination IP and port of `deliver_sm_resp`   |
| `originator_addr`    | Sender's address (from Deliver_SM)             |
| `recipient_addr`     | Recipient's mobile number                      |
| `message_content`    | Text of the message or delivery receipt        |

### Requirements

- Python 3.x
- Django (see `requirements.txt` for exact version)
- Other dependencies as listed in `requirements.txt`

### Setup

1. **Clone the repository:**

   ```bash
   git clone git@github.com:onex-saksham/Smpp_loss.git
   cd Smpp_loss
   ```

2. **Create and activate a virtual environment:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Apply migrations:**

   ```bash
   python manage.py migrate
   ```

5. **Create a superuser (optional, for admin access):**

   ```bash
   python manage.py createsuperuser
   ```

6. **Run the development server:**

   ```bash
   python manage.py runserver
   ```

7. **Access the project:**

   - Open your browser and go to `http://127.0.0.1:8000/`

---

> **Note:** This is an internal project for visualizing SMPP PDU chains within Onextel Network and should not be used in production.


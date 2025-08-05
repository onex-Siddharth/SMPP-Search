## SMPP PDU Chain Visualizer

### Usage

1. **Input PCAP Directory**:

   * Enter the directory path containing your PCAP files in the first input box. If no directory is provided, the project will default to using PCAP files from the project root directory.

2. **Generate CSV**:

   * Click **Generate CSV**. The code parses all PCAP files in the selected directory and saves the extracted SMPP PDU data into CSV files for easy searching and analysis.

3. **Download CSV**:

   * Click **Download Full Chain CSV** to download the complete CSV containing all message chains.

4. **Search by Criteria**:

   * In the search bar you can now enter one or more comma-separated values for any of these fields:

     * **message\_id** (Telco ID)
     * **submit\_src** (source IP\:port)
     * **submit\_dst** (destination IP\:port)
   * The results table will display only the chains matching any of the entered values.

### Socket Summary View

After generating the CSV, the interface displays a **Socket Summary Table**, which aggregates SMPP PDU chains by their source and destination socket pairs (`submit_src` → `submit_dst`).

Each row in this table represents a unique connection pair and displays:

| Column Name              | Description                                                           |
| ------------------------ | --------------------------------------------------------------------- |
| `Submit Src`             | IP and port of the sender in `submit_sm` PDUs                         |
| `Submit Dst`             | IP and port of the receiver in `submit_sm` PDUs                       |
| `Total Submit`           | Total number of `submit_sm` PDUs                                      |
| `Matched Submit_Resp`    | Number of `submit_sm` PDUs with matching `submit_sm_resp`             |
| `Unmatched Submit_Resp`  | Number of `submit_sm` PDUs with no matching response                  |
| `Matched Deliver`        | Number of `deliver_sm` PDUs that matched expected flows               |
| `Unmatched Deliver`      | Number of `deliver_sm` PDUs without expected pairings                 |
| `Matched Deliver_Resp`   | Number of `deliver_sm` PDUs with proper `deliver_sm_resp`             |
| `Unmatched Deliver_Resp` | Number of `deliver_sm` PDUs without a corresponding `deliver_sm_resp` |
| `View Missing` Buttons   | Links to inspect unmatched PDUs individually                          |
| `Download`               | Allows downloading the CSV specific to this socket pair               |

This view helps quickly identify issues like packet loss or incomplete messaging across any individual TCP connection.

### Unmatched PDU Inspection

Clicking the "View" button under any unmatched count column will take you to a detailed page listing each unmatched PDU.

For example, in the **Unmatched Submit Resp** view:

| Field              | Description                              |
| ------------------ | ---------------------------------------- |
| `packet_no_submit` | Packet number where `submit_sm` was seen |
| `submit_sm_seq`    | Sequence number of the `submit_sm`       |
| `submit_time`      | Timestamp when `submit_sm` was sent      |
| `submit_src`       | IP and port that sent the `submit_sm`    |
| `submit_dst`       | IP and port that was supposed to respond |
| `message_id`       | Message ID assigned (if applicable)      |
| `recipient_addr`   | Intended recipient of the message        |

This helps isolate specific communication failures and inspect exact packet loss instances for network debugging.

#### Table Columns Explained

| Column Name         | Description                                    |
| ------------------- | ---------------------------------------------- |
| `message_id`        | Unique ID assigned to the message by the telco |
| `submit_sm_seq`     | Sequence number of the `submit_sm` PDU         |
| `submit_time`       | Timestamp when `submit_sm` was sent            |
| `submit_src`        | Source IP and port of `submit_sm`              |
| `submit_dst`        | Destination IP and port of `submit_sm`         |
| `submit_resp_time`  | Timestamp when `submit_sm_resp` was received   |
| `submit_resp_src`   | Source IP and port of `submit_sm_resp`         |
| `submit_resp_dst`   | Destination IP and port of `submit_sm_resp`    |
| `deliver_seq`       | Sequence number of the `deliver_sm` PDU        |
| `deliver_time`      | Timestamp when `deliver_sm` was sent           |
| `deliver_src`       | Source IP and port of `deliver_sm`             |
| `deliver_dst`       | Destination IP and port of `deliver_sm`        |
| `deliver_resp_time` | Timestamp when `deliver_sm_resp` was received  |
| `deliver_resp_src`  | Source IP and port of `deliver_sm_resp`        |
| `deliver_resp_dst`  | Destination IP and port of `deliver_sm_resp`   |
| `originator_addr`   | Sender's address (from Deliver\_SM)            |
| `recipient_addr`    | Recipient's mobile number                      |
| `message_content`   | Text of the message or delivery receipt        |

### Requirements

* Python 3.x
* Django (see `requirements.txt` for exact version)
* Other dependencies as listed in `requirements.txt`

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

   * Open your browser and go to `http://127.0.0.1:8000/`

---

> **Note:** This is an internal project for visualizing SMPP PDU chains within Onextel Network and should not be used in production.

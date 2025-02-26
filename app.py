import re
import pandas as pd
import pymysql
import os
import pickle
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import streamlit as st
from datetime import datetime, timedelta
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import time
import supabase
import openai
import json
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")


supabase_client = supabase.create_client(SUPABASE_URL, SUPABASE_KEY)


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Database connection function
def get_db_connection():
    """Establish and return a database connection."""
    return supabase_client

# Authenticate Gmail API
def authenticate_gmail():
    """Authenticate and return the Gmail API service."""
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=8081)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return build('gmail', 'v1', credentials=creds)

# Extract lender name
"""def extract_lender_name(from_field):
    Extract lender name from the 'From' field of the email.
    if not from_field:
        return None
    
     # If 'via' is present, remove it and keep only the email address part
    if "via" in from_field:
        from_field = from_field.split(" via")[0].strip()
    match = re.search(r'<([^>]+)>', from_field)
    email = match.group(1) if match else from_field.strip()
    if '@' in email:
        domain_name = email.split('@')[1]
        domain_name_base = domain_name.split('.')[0]
        return domain_name_base.lower()
    return None"""

# Parse subject for business name
"""def parse_subject_for_business_name(subject):
    Parse the subject line to extract the business name.
    try:
        if not subject:
            return "Unable to parse"
        # Specific condition: Approval with business name and amount

        if "Approval for $" in subject and "DBA" in subject:
            parts = subject.split(" ")
            dba_index = parts.index("DBA")
            if dba_index > 0 and dba_index + 1 < len(parts):
                return " ".join(parts[dba_index + 1:]).strip()
        if " - " in subject:
            parts = subject.split(" - ")
            if len(parts) >= 3:
                return parts[-1].strip()
        if "Congratulations! Your deal for" in subject and "has been approved" in subject:
            start = subject.find("Congratulations! Your deal for") + len("Congratulations! Your deal for")
            end = subject.find("has been approved")
            return subject[start:end].strip().strip('"')
        
        # Condition: Decline notice with "business name"
        if "Decline Notice. Unfortunately, we are not able to approve your file at this time for" in subject:
            start = subject.find("Decline Notice. Unfortunately, we are not able to approve your file at this time for") + len("Decline Notice. Unfortunately, we are not able to approve your file at this time for")
            return subject[start:].strip().strip('"')
         # Condition: "Missing Docs for 'business name'"
        if "Missing Docs for" in subject:
            start = subject.find("Missing Docs for") + len("Missing Docs for")
            return subject[start:].strip().strip('"')

        # Condition: "Decline for 'business name'"
        if "Decline for" in subject:
            start = subject.find("Decline for") + len("Decline for")
            return subject[start:].strip().strip('"')
             # Condition: "'Business name' Decline Notification: Your Application Has Been Declined"
        if "Decline Notification: Your Application Has Been Declined" in subject:
            end = subject.find(" Decline Notification: Your Application Has Been Declined")
            return subject[:end].strip().strip('"')
        if "for business name:" in subject:
            start = subject.find("for business name:") + len("for business name:")
            return subject[start:].split()[0].strip()
        if "Application for" in subject and "has been Declined" in subject:
            start = subject.find("Application for") + len("Application for")
            end = subject.find("has been Declined")
            return subject[start:end].strip()
        if "Unfortunately, we are not able to approve your file at this time for" in subject:
            start = subject.find("Unfortunately, we are not able to approve your file at this time for") + len("Unfortunately, we are not able to approve your file at this time for")
            return subject[start:].strip().strip('"')
        # Condition: "Application submission for 'business name' with ID 11111 declined"
        if "Application submission for" in subject and "with ID" in subject and "declined" in subject:
            start = subject.find("Application submission for") + len("Application submission for")
            end = subject.find("with ID")
            return subject[start:end].strip().strip('"')
          # Condition: "FNX - Application # 372080 for 'business name:' Declined"
        if "FNX - Application" in subject and "for" in subject and "Declined" in subject:
            start = subject.find("for") + len("for")
            end = subject.find("Declined")
            return subject[start:end].strip().strip('"')
          # Condition: Congratulations! SFC is considering an offer for 'business name'
        if "SFC is considering an offer for" in subject:
            start = subject.find("SFC is considering an offer for") + len("SFC is considering an offer for")
            return subject[start:].strip().strip('"')
        if "Your deal for" in subject and "has Missing Information" in subject:
            start = subject.find("Your deal for") + len("Your deal for")
            end = subject.find("has Missing Information")
            return subject[start:end].strip()
        if "Your deal for" in subject and "has been Approved" in subject:
            start = subject.find("Your deal for") + len("Your deal for")
            end = subject.find("has been Approved")
            return subject[start:end].strip()
        
        if "Torro Submission" in subject and "(" in subject and ")" in subject:
            start = subject.find("(") + 1
            end = subject.find(")")
            return subject[start:end].strip()
        if subject.startswith("AFP OFFERS-") and "Lead ID" in subject and "-" in subject:
            match = re.search(r"-([^-]+)$", subject)
            if match:
             return match.group(1).strip()
        if "Approval Offer:" in subject:
            start = subject.find(":") + 1
            extracted_text = subject[start:].strip()
            if subject.endswith(extracted_text):
                return extracted_text
        if subject.endswith("Wellen Capital, LLC") and "- Status Update -" in subject:
           start = subject.find("- Status Update -")
           extracted_text = subject[:start].strip()
           return extracted_text

        if "Submission Declined for" in subject:
            start = subject.find("Submission Declined for") + len("Submission Declined for")
            end = subject.find(" - ", start)
            return subject[start:end].strip() if end != -1 else subject[start:].strip()
        if "New sub -(Pathway Catalyst)" in subject:
            start = subject.find("New sub -(Pathway Catalyst)") + len("New sub -(Pathway Catalyst)")
            return subject[start:].strip()
        return "Unable to parse"
    except Exception:
        return "Unable to parse" """

# Check matches in the database using fuzzy matching
def check_matches_in_db(lender_name, business_name):
    """Check for fuzzy matches with lender names and business names in the deals_submitted table in Supabase."""
    try:
        query = "SELECT lender_names, business_name FROM deals_submitted"
        response = supabase_client.table("deals_submitted").select("lender_names, business_name").execute()
        
        if response and response.data:
            df = pd.DataFrame(response.data)
        else:
            return False, False

        # Initialize match flags
        lender_match = False
        business_match = False

        if lender_name:
            df['lender_score'] = df['lender_names'].apply(
                lambda x: fuzz.partial_ratio(lender_name.lower(), x.lower()) if isinstance(x, str) else 0
            )
            lender_match = df['lender_score'].max() > 80

        if business_name and business_name != "Unable to parse":
            df['business_score'] = df['business_name'].apply(
                lambda x: fuzz.partial_ratio(business_name.lower(), x.lower()) if isinstance(x, str) else 0
            )
            business_match = df['business_score'].max() > 80

        return lender_match, business_match
    except Exception as e:
        st.error(f"Database query failed: {e}")
        return False, False


# Classify and Insert processed emails into the database

def classify_and_insert_declines(email_df):
    """Classify emails using an OpenAI Assistant and insert structured decline reasons into the `declines` table in Supabase."""
    try:
        assistant_id = os.getenv("OPENAI_ASSISTANT_ID")  # Fetch Assistant ID from environment variable
        gpt_key = os.getenv("OPENAI_API_KEY")  # Fetch GPT API key from environment variable
        
        if not assistant_id or not gpt_key:
            st.error("Missing OpenAI Assistant ID or API Key in environment variables.")
            return

        openai.api_key = gpt_key  # Set the OpenAI API key
        
        for _, row in email_df.iterrows():
            # Create a thread for classification
            thread = openai.beta.threads.create()
            
            # Run the assistant to classify the email snippet
            run = openai.beta.threads.runs.create(
                thread_id=thread.id,
                assistant_id=assistant_id,
                messages=[{"role": "user", "content": row['snippet']}]
            )
            
            # Wait for completion
            while True:
                run_status = openai.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)
                if run_status.status == "completed":
                    break
            
            # Fetch the response from the assistant
            messages = openai.beta.threads.messages.list(thread_id=thread.id)
            response_content = messages.data[0].content[0].text.value if messages.data else "{}"
            classification_data = json.loads(response_content) if response_content else {}

            if not classification_data:
                continue
            
            # Insert structured data into the declines table
            insert_query = {
                "business_name": classification_data.get("business_name", "Unknown"),
                "lender_names": classification_data.get("lender_name", "Unknown"),
                "decline_reason": classification_data.get("decline_reason", "Unspecified")
            }
            
            response = supabase_client.table("declines").insert(insert_query).execute()
            
            if response.get('error'):
                st.error(f"Database insert failed: {response['error']}")
    
    except Exception as e:
        st.error(f"Database operation failed: {e}")


def fetch_classified_data():
    """Fetch classified decline data from the `declines` table in Supabase."""
    try:
        response = supabase_client.table("declines").select("*").execute()
        
        if response and response.data:
            classified_df = pd.DataFrame(response.data)
            return classified_df
        else:
            return pd.DataFrame()
    except Exception as e:
        st.error(f"Database error: {e}")
        return pd.DataFrame()
    
# Main application
def main():
    """Main function to display classified decline data from the bot."""
    st.title("Classified Declines Dashboard")
    
    # Fetch classified data
    classified_data = fetch_classified_data()
    
    if not classified_data.empty:
        st.write("### Classified Declined Emails")
        st.dataframe(
            classified_data.style.format({
                'created_at': lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if isinstance(x, str) else x,
            }).set_table_styles([
                {'selector': 'thead th', 'props': [('background-color', '#f2f2f2'), ('font-weight', 'bold')]},
                {'selector': 'tbody td', 'props': [('text-align', 'left'), ('font-size', '17px'), ('padding', '10px')]},
                {'selector': 'thead', 'props': [('border-bottom', '2px solid #D9534F')]},
            ], overwrite=True),
            use_container_width=True
        )
    else:
        st.warning("⚠️ No classified declines found in the `declines` table.")


if __name__ == "__main__":
    main()

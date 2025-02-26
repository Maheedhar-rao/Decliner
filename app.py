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
def fetch_latest_emails():
    """Fetch the latest unread emails from Gmail."""
    try:
        service = authenticate_gmail()

        # Fetch unread emails
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q="is:unread").execute()
        messages = results.get("messages", [])

        email_data = []
        for msg in messages:
            msg_details = service.users().messages().get(userId='me', id=msg["id"]).execute()

            # Extract email metadata
            headers = msg_details.get("payload", {}).get("headers", [])
            snippet = msg_details.get("snippet", "")

            # Extract sender and subject
            sender = next((header["value"] for header in headers if header["name"] == "From"), "Unknown Sender")
            subject = next((header["value"] for header in headers if header["name"] == "Subject"), "No Subject")

            email_data.append({"sender": sender, "subject": subject, "snippet": snippet})

            # Mark email as read (optional)
            service.users().messages().modify(userId='me', id=msg["id"], body={"removeLabelIds": ["UNREAD"]}).execute()

        return pd.DataFrame(email_data) if email_data else pd.DataFrame()
    
    except Exception as e:
        st.error(f"Error fetching emails: {e}")
        return pd.DataFrame()


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
    """Main function to continuously fetch, classify, and display classified decline data."""
    st.title("Classified Declines Dashboard")

    # Fetch & classify new emails automatically every 5 minutes
    if st.button("Fetch New Emails"):
        with st.spinner("Fetching and processing new emails..."):
            email_df = fetch_latest_emails()
            if not email_df.empty:
                classify_and_insert_declines(email_df)
            else:
                st.success("No new unread emails.")

    # Auto-refresh data every 5 minutes
    while True:
        st.write("Checking for new emails...")
        email_df = fetch_latest_emails()
        if not email_df.empty:
            classify_and_insert_declines(email_df)
        time.sleep(300)  # Wait 5 minutes

        # Refresh dashboard with new classified declines
        classified_data = fetch_classified_data()
        if not classified_data.empty:
            st.write("### Classified Declined Emails")
            st.dataframe(classified_data)
        else:
            st.warning("⚠️ No classified declines found in Supabase.")


if __name__ == "__main__":
    main()

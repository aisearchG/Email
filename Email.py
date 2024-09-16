import os
import base64
import re
from datetime import datetime, timedelta
import email
from email.header import decode_header
import pandas as pd
import streamlit as st
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode
import bleach  # For sanitizing HTML content in emails

# Define the scope for Gmail API (read-only access)
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def fetch_emails(_service, days):
    """
    Fetches emails from the user's Gmail account within the specified number of days.
    Extracts date, sender, subject, snippet, and full body for each email.

    Parameters:
    - _service: Gmail API service instance
    - days (int): Number of days back to fetch emails from

    Returns:
    - List of dictionaries containing email details
    """
    # Calculate the date 'days' ago from today
    now = datetime.utcnow()
    start_date = now - timedelta(days=days)
    query = f'after:{start_date.strftime("%Y/%m/%d")}'

    try:
        # Retrieve messages matching the query
        results = _service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
    except Exception as e:
        st.error(f"An error occurred while fetching emails: {e}")
        return []

    emails = []
    if not messages:
        st.info('No messages found.')
    else:
        for message in messages:
            try:
                # Get the message details
                msg = _service.users().messages().get(userId='me', id=message['id'], format='full').execute()
                headers = msg['payload']['headers']
                snippet = msg.get('snippet', '')
                date_ = from_ = subject = ''
                body = ''
                message_id = msg.get('id', '')

                # Parse headers
                for header in headers:
                    if header['name'] == 'Subject':
                        subject, encoding = decode_header(header['value'])[0]
                        if isinstance(subject, bytes):
                            subject = subject.decode(encoding if encoding else 'utf-8')
                    elif header['name'] == 'From':
                        from_ = header['value']
                    elif header['name'] == 'Date':
                        date_raw = header['value']
                        date_clean = re.sub(r' \(.*\)', '', date_raw)
                        date_tuple = email.utils.parsedate_tz(date_clean)
                        if date_tuple:
                            date_ = datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))

                # Extract the email body
                if msg['payload']['body'] and 'data' in msg['payload']['body']:
                    try:
                        body = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')
                    except Exception:
                        body = "No Body Available"
                else:
                    # If the email has parts, iterate through them to find the plain text or HTML part
                    parts = msg['payload'].get('parts', [])
                    for part in parts:
                        if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                            try:
                                body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                                break  # Stop after finding the first text/plain part
                            except Exception:
                                body = "No Body Available"
                        elif part['mimeType'] == 'text/html' and 'data' in part['body']:
                            try:
                                body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                                break  # Stop after finding the first text/html part
                            except Exception:
                                body = "No Body Available"

                # Append the email data with Message ID
                emails.append({
                    'Message ID': message_id,
                    'Date': date_.strftime('%Y-%m-%d %H:%M:%S') if date_ else 'N/A',
                    'From': from_,
                    'Subject': subject,
                    'Snippet': snippet,
                    'Body': body
                })

            except Exception:
                continue

    return emails


def parse_sender_info(sender):
    """
    Parses the sender's name and email address from the 'From' field.

    Parameters:
    - sender (str): The raw 'From' header value

    Returns:
    - Tuple containing the sender's name and email address
    """
    match = re.match(r'(.*?)(<.*?>)', sender)
    if match:
        name = match.group(1).strip().strip('"')
        email_address = match.group(2).strip('<>')
    else:
        name = sender
        email_address = ''
    return name, email_address


def main():
    # Initialize Streamlit page configuration
    st.set_page_config(page_title="📧 Email Explorer", layout="wide")

    # Display logo or image if available
    # Ensure 'aislogp.png' is in the same directory or provide the correct path
    if os.path.exists("aislogp.png"):
        st.image("aislogp.png")
    else:
        st.write("![Logo](https://via.placeholder.com/150)")

    st.title("📧 Email Explorer")

    # Initialize OAuth2 credentials
    if 'creds' not in st.session_state:
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
            st.session_state.creds = creds
        else:
            st.session_state.creds = None
    else:
        creds = st.session_state.creds

    # If no valid credentials, prompt the user to log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                st.session_state.creds = creds
                st.success("Credentials refreshed successfully.")
            except Exception as e:
                st.error(f"Failed to refresh credentials: {e}")
        else:
            try:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
                st.session_state.creds = creds
                st.success("Authentication successful.")
            except Exception as e:
                st.error(f"Failed to authenticate: {e}")
                st.stop()
        # Save the credentials for future use
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    # Build the Gmail service
    try:
        service = build('gmail', 'v1', credentials=creds)
    except Exception as e:
        st.error(f"Failed to build Gmail service: {e}")
        st.stop()

    # Sidebar Inputs
    st.sidebar.header("📋 Settings")

    days = st.sidebar.number_input(
        "⏳ Number of Days to Retrieve Emails:",
        min_value=1,
        max_value=365,
        value=7,
        step=1
    )

    # Button to fetch emails
    fetch_button = st.sidebar.button("📥 Fetch Emails")

    if fetch_button:
        with st.spinner('📤 Fetching emails...'):
            # Fetch emails using the fetch_emails function
            emails = fetch_emails(service, days)
            # Store fetched emails in session_state
            st.session_state.emails = emails

    # Check if emails are stored in session_state
    if 'emails' in st.session_state:
        emails = st.session_state.emails
        if emails:
            # Create DataFrame
            df = pd.DataFrame(emails)

            # Display the DataFrame in AgGrid with row selection
            st.subheader(f"📬 Emails from the last {days} day(s):")

            # Configure AgGrid
            display_df = df[['Message ID', 'Date', 'From', 'Subject', 'Snippet']]

            gb = GridOptionsBuilder.from_dataframe(display_df)
            gb.configure_pagination(paginationAutoPageSize=True)  # Enable pagination with automatic page size
            gb.configure_side_bar()  # Enable sidebar for column visibility and filters
            gb.configure_selection(selection_mode='single', use_checkbox=False)  # Enable single row selection
            gb.configure_default_column(resizable=True, sortable=True, filter=True)  # Enable resizing, sorting, and filtering for all columns
            gb.configure_column('Message ID', hide=True, editable=False)  # Hide Message ID

            gridOptions = gb.build()

            grid_response = AgGrid(
                display_df,
                gridOptions=gridOptions,
                height=400,
                width='100%',
                update_mode=GridUpdateMode.SELECTION_CHANGED,
                theme='streamlit',  # Use 'streamlit' theme
                enable_enterprise_modules=False,
                allow_unsafe_jscode=True,  # Allow custom JS if needed
                data_return_mode='AS_INPUT',  # Ensure selected_rows is a list
            )

            selected = grid_response['selected_rows']

            # Ensure 'selected' is a list of dictionaries
            if isinstance(selected, pd.DataFrame):
                # Convert DataFrame to list of dicts
                selected = selected.to_dict('records')

            # Check if 'selected' is a non-empty list
            if isinstance(selected, list) and selected:
                selected_row = selected[0]
                message_id = selected_row['Message ID']

                # Retrieve the full email body using the message ID
                email_body = next(
                    (email['Body'] for email in emails if email['Message ID'] == message_id),
                    "No Body Available"
                )

                st.markdown("---")
                st.subheader("📄 Email Details")

                # Parse sender information
                name, email_address = parse_sender_info(selected_row['From'])

                st.markdown(f"**From:** {name} &lt;{email_address}&gt;")
                st.markdown(f"**Subject:** {selected_row['Subject']}")
                st.markdown(f"**Date:** {selected_row['Date']}")
                st.markdown("**Body:**")

                # Detect if the email body contains HTML tags and sanitize
                if bool(re.search(r'<[^>]+>', email_body)):
                    # Sanitize the HTML content to prevent XSS attacks
                    cleaned_body = bleach.clean(
                        email_body,
                        tags=bleach.sanitizer.ALLOWED_TAGS.union({'p', 'br', 'strong', 'em', 'ul', 'ol', 'li'}),
                        strip=True
                    )
                    st.markdown(cleaned_body, unsafe_allow_html=True)
                else:
                    st.text_area("", value=email_body, height=300)
            else:
                st.info("Select an email row to view its details.")
        else:
            st.warning("⚠️ No emails retrieved. Please check your credentials and settings.")

    # Optional: Add a description or instructions
    st.markdown("""
    ---
    **Instructions:**
    1. Use the sidebar to specify the number of days for which you want to retrieve emails.
    2. Click on the "📥 Fetch Emails" button to load your emails.
    3. The emails will be displayed in the table below, showing the date, sender, subject, and a snippet of the email body.
    4. Click on any row in the table to view the full content of that email.
    """)


if __name__ == '__main__':
    main()

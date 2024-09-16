import streamlit as st

def main():
    st.title("Test HTML Rendering")
    html_content = """
    <h1>Hello, Streamlit!</h1>
    <p>This is a <strong>test</strong> of HTML rendering.</p>
    <table>
        <tr><th>Header 1</th><th>Header 2</th></tr>
        <tr><td>Data 1</td><td>Data 2</td></tr>
    </table>
    """
    st.markdown(html_content, unsafe_allow_html=True)

if __name__ == "__main__":
    main()

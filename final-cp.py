import requests
from bs4 import BeautifulSoup
import dns.resolver
import socket
import re
import whois
import argparse
import csv

def step8():
   
    parser = argparse.ArgumentParser(description='Process some inputs.')
    parser.add_argument('--text', type=str, help='process some text')

    args = parser.parse_args()

    if args.text is not None:
        print(f"Processing text: {args.text}")
    return args.text    

vorodi = step8()
print('site map:')
def site_map(url):
    # darkhast be site
    response = requests.get(url)
    
    # if darkhast true!
    if response.status_code == 200:
        # gereftan mohtavaye site ba bs4
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # find all a tags
        links = soup.find_all('a')
        
        # estekhraj url az har a
        urls = [link.get('href') for link in links if link.get('href')]
        
        return urls
    else:
        print(f"Failed to retrieve the web page. Status code: {response.status_code}")
        return []

url = 'https://'+ vorodi
links = site_map(url)
for link in links:
    print(link)


def sub_domain():
    domain = vorodi


    ns = dns.resolver.query(domain, 'NS')


    subdomains = ["api", "www", "mail", "ftp", "blog", "test", "dev", "staging", "docs", "shop",
                "support", "help", "forum", "status", "beta", "demo", "app", "secure", "static", "cdn"]


    for server in ns:
        server = str(server)
        for subdomain in subdomains:
            try:
                answers = dns.resolver.query(subdomain + "." + domain, "A")
                for ip in answers:
                    print(subdomain + "." + domain + " - " + str(ip))
            except:
                pass
subway=sub_domain()
sub_domain()

print("title:")
def title(vorodi):
    url = "https://" + vorodi

    response = requests.get(url)

    soup = BeautifulSoup(response.content, 'html.parser')

    title_tag = soup.title

    if title_tag:

        title = title_tag.string
    else:
        title = "no title"

    print(title)

tilit=title(vorodi)
title(vorodi)
print("status:")
def status():
    url = "https://"+vorodi
#darkhast  zadan be site
    response = requests.get(url)

    # Check the HTTP status code of the response
    if response.status_code == 200:
        return "Success!"
       
    elif response.status_code == 301:
        return"301:Moved Permanently!"
    elif response.status_code == 302:
        return"302:found!"
    elif response.status_code == 400:
        return"400:bad requests!"
    elif response.status_code == 401:
        return"401:Unauthorized!"
    elif response.status_code == 403:
        return"403:Forbidden!"
    elif response.status_code == 404:
        return"404:Not found!"
    elif response.status_code == 500:
        return"500:Internal Server Error!"

statusReturn = status()
status()
print("ip:")
def ip():
    domain = vorodi

    ip_address = socket.gethostbyname(domain)

    print(f"The IP address of {domain} is {ip_address}")

iq=ip()
ip()
print("port:")
def port():
    domain = vorodi
    ip = ip_address = socket.gethostbyname(domain)

    # List of commonly used ports to scan
    common_ports = [21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 993, 995]

    for port in common_ports:  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set timeout to 1 second
        result = sock.connect_ex((ip, port))
        if result == 0:
            print("Port {} is open".format(port))
        else:
            print("Port {} is closed".format(port))
        sock.close()

porrrt=port()
port()

def regex(url):
    
    def extract_contacts_from_website(url):
        try:
            # peyda kardan mohtava
            response = requests.get(url)
            response.raise_for_status()  #barresi vojod error
        except requests.RequestException as e:
            print(f"Failed to retrieve the website content: {e}")
            return [], []

        emails = re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', response.text)
       
       
        phone_numbers = re.findall(r"\d{3}-\d{8}", response.text)
        
        return emails, phone_numbers

    # dar avardan email va shomare
    emails, phone_numbers = extract_contacts_from_website(url)

   
    print("emails:")
    for email in emails:
        print(email)

    print("\nphone numbers:")
    for number in phone_numbers:
        print("phone number:", number)

# استفاده از تابع
website_url = "https://"+ vorodi
rejex=regex(website_url)
regex(website_url)


def hoois():
    domain = vorodi

    w = whois.whois(domain)

    print(w)

    # Safely print each field if it exists
    print("Domain registrar:", w.registrar if hasattr(w, 'registrar') else "N/A")
    print("WHOIS server:", w.whois_server if hasattr(w, 'whois_server') else "N/A")
    print("Domain creation date:", w.creation_date if hasattr(w, 'creation_date') else "N/A")
    print("Domain expiration date:", w.expiration_date if hasattr(w, 'expiration_date') else "N/A")
    print("Domain last updated:", w.last_updated if hasattr(w, 'last_updated') else "N/A")
    print("Name servers:", w.name_servers if hasattr(w, 'name_servers') else "N/A")
    print("Registrant name:", w.name if hasattr(w, 'name') else "N/A")
    print("Registrant organization:", w.org if hasattr(w, 'org') else "N/A")
    print("Registrant email:", w.email if hasattr(w, 'email') else "N/A")
    print("Registrant phone:", w.phone if hasattr(w, 'phone') else "N/A")

hooiz=hoois()
hoois()
def report (site_map,sub_domain,title,status,port, ip,regex,hoois):
    
    filename = "data.csv"

    # writing to csv file
    with open(filename, 'w') as csvfile:
        # creating a csv writer object
        csvwriter = csv.writer(csvfile)

        # writing the data rows
        csvwriter.writerows(site_map)
        csvwriter.writerows(sub_domain)
        csvwriter.writerows(title)
        csvwriter.writerows(status)
        csvwriter.writerows(port)
        csvwriter.writerows(ip)
        csvwriter.writerows(regex)
        csvwriter.writerows(hoois)

report(links,statusReturn,porrrt,hooiz,rejex,tilit,iq,subway)      
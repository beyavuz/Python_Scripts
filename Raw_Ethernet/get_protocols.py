import json

from bs4 import BeautifulSoup
import requests


def get_protocols_list():
    page = requests.get('https://sites.uclouvain.be/SystInfo/usr/include/linux/if_ether.h.html')
    soup = BeautifulSoup(page.content, 'html.parser')
    constant_list = []
    for tag in soup.find_all('strong')[7:]:
        """
        print(list(filter(lambda x: x != "", tag.findChildren('font')[0].text.split(" "))),
              tag.findChildren('font')[1].text.replace("/*", "").replace("*/", "").strip())
        """
        _, name, value = list(filter(lambda x: x != "", tag.findChildren('font')[0].text.split(" ")))
        explanation = tag.findChildren('font')[1].text.replace("/*", "").replace("*/", "").strip()
        # data = {value: {"name": name, "exp": explanation}}
        data = {"value": value.lower(), "name": name, "exp": explanation}
        constant_list.append(data)

    with open('protocol_eth.json', 'w') as file:
        json.dump(constant_list, file, indent=2)

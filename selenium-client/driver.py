from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select, WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException
import time
import threading
import click


class StartDriver:
    
    def __init__(self, browser: str, executable=False) -> None:
        self.browser = browser
        
        # If executable == True, then it runs based off of the executable name
        # Relative path to browser driver executable
        relative_path = "./drivers/"
        
        if browser.lower() == "firefox":
            if executable:
                drivername = "{}geckodriver".format(relative_path)
                self.driver = webdriver.Firefox(executable_path=drivername)
            else:
                self.driver = webdriver.Firefox()
            
        elif browser.lower() == "chrome":
            if executable:    
                drivername = "{}chromedriver".format(relative_path)
                self.driver = webdriver.Chrome(executable_path=drivername)
            else:
                self.driver = webdriver.Chrome()
            
        elif browser.lower() == "safari":
            self.driver = webdriver.Safari()
            
        elif browser.lower() == "internet explorer":
            # Windows only
            if executable:
                drivername = "{}iedriver".format(relative_path)
                self.driver = webdriver.Ie(executable_path=drivername)
            else:
                self.driver = webdriver.Ie()
            
        elif browser.lower() == "edge":
            if executable:
                drivername = "{}msedgedriver".format(relative_path)
                self.driver = webdriver.Edge(executable_path=drivername)
            else:
                self.driver = webdriver.Edge()
            
        else:
            raise Exception("A valid browser must be selected")
        
        
    def run_experiment(self, uniqname="skorman", network="UMich WiFi", vpn=False, provider="IPVanish", vpn_loc="Michigan", your_loc="Ann Arbor, MI, USA"):
        self.driver.get("https://test.reethika.info/measure")
        # Fill uniqname field, wait for element to be clickable
        uniqname_elem = WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable((By.NAME, "email")))
        uniqname_elem.send_keys(uniqname)
        
        # Select Desktop
        devices = self.driver.find_elements(By.NAME, "device")
        devices[1].click()
        
        # Fill network field
        network_elem = self.driver.find_element(By.NAME, "network")
        network_elem.send_keys(network)
        
        # Fill browser field
        browser_elem = Select(self.driver.find_element(By.ID, "browser"))
        browser_elem.select_by_value(self.browser)
        
        vpn_select_elem = self.driver.find_elements(By.NAME, "exp_type")
        if not vpn:
            vpn_select_elem[0].click()
        else:
            vpn_select_elem[1].click()
            # Wait until element is ready to be interactable
            name_vpn = WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable((By.NAME, "name_vpn")))
            name_vpn.send_keys(provider)
            self.driver.find_element(By.NAME, "location_vpn").send_keys(vpn_loc)
            self.driver.find_element(By.NAME, "location_user").send_keys(your_loc)

        # Wait until element is clickable
        submit_btn = WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable((By.XPATH, "/html/body/form/input[7]")))
        submit_btn.click()
        
        self.wait_for_completion()
        

    def element_exists(self, elem_id):
        try:
            self.driver.find_element(By.ID, elem_id)
        except NoSuchElementException:
            return False
        return True
        
        
    def wait_for_completion(self):
        counter = 0
        while not self.element_exists("status"):
            time.sleep(0.25)
        while self.driver.find_element(By.ID, "status").text != "Done" and counter < 150:
            counter += 1
            time.sleep(1)
            
        print("Browser:", self.browser, "finished!")
        self.driver.quit()


def run_browser_test(browser, options):
    driver = StartDriver(browser)
    driver.run_experiment(**options)


def run_all_browser_tests(browsers: list, options):
    threads: list[threading.Thread] = []
    for browser in browsers:
        if browser == "safari":
            time.sleep(4)
        browser_thread = threading.Thread(target=run_browser_test, args=[browser, options])
        browser_thread.start()
        threads.append(browser_thread)
        
    for thread in threads:
        thread.join()
        
@click.command()
@click.option('-u', '--uniqname', default='skorman', help='Uniqname of person running test')
@click.option('-n', '--network', default='UMich WiFi', help='Network connected to (e.g. UMich WiFi, Comcast Home, T-Mobile, Verizon)')
@click.option('--vpn', is_flag=True, help='Indicate whether running through a VPN')
@click.option('-p', '--provider', default="IPVanish", help="VPN Provider Name and Server")
@click.option('-l', '--vpn_loc', help='Location of VPN (City, State, Country)')
@click.option('-y', '--your_loc', default='Ann Arbor, MI, USA', help='Your location (City, State, Country)')
@click.option('-s', '--safari', is_flag=True, help='Indicate whether to only run Safari')
def main(safari=False, **kwargs):
    allowable_browsers = ["chrome", "firefox", "safari"]
    if safari:
        allowable_browsers = ["safari"]
        
    if kwargs['vpn'] and not kwargs['vpn_loc']:
        raise Exception('You must provide VPN server location using -l flag if using a VPN (Please enter "unknown" if you are unsure about your VPN server\'s location, or "best available" if you chose that in your VPN settings)')
    
    run_all_browser_tests(allowable_browsers, kwargs)



if __name__ == "__main__":
    main()
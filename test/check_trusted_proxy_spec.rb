require File.expand_path('spec_helper', File.dirname(__FILE__))

describe "check trusted proxy resolver module" do
  it "should resolve to last x-forwarded-for ip when remote address is from google proxy" do
    nginx_run_server({address: "$http_x_origin_ip"}, timeout: 10) do
      EventMachine.run do
        sub = EventMachine::HttpRequest.new("#{nginx_address}/resolved").get(head: {"x-origin-ip" => "66.249.81.131", "x-forwarded-for" => "10.2.10.23, 222.111.123.21"})
        sub.callback do
          expect(sub).to be_http_status(200)
          expect(sub.response).to be === "222.111.123.21"
          EventMachine.stop
        end
      end
    end
  end

  it "should not resolve to last x-forwarded-for ip when remote address isn't from google proxy" do
    nginx_run_server({address: "$http_x_origin_ip"}, timeout: 10) do
      EventMachine.run do
        sub = EventMachine::HttpRequest.new("#{nginx_address}/resolved").get(head: {"x-origin-ip" => "66.249.64.10", "x-forwarded-for" => "10.2.10.23, 222.111.123.21"})
        sub.callback do
          expect(sub).to be_http_status(200)
          expect(sub.response).to be === "66.249.64.10"

          EventMachine.stop
        end
      end
    end
  end

  it "should not resolve to last x-forwarded-for ip when remote address is from google proxy but resolver is off" do
    nginx_run_server({address: "$http_x_origin_ip", to_real_ip: "off"}, timeout: 10) do
      EventMachine.run do
        sub = EventMachine::HttpRequest.new("#{nginx_address}/resolved").get(head: {"x-origin-ip" => "66.249.81.131", "x-forwarded-for" => "10.2.10.23, 222.111.123.21"})
        sub.callback do
          expect(sub).to be_http_status(200)
          expect(sub.response).to be === "66.249.81.131"
          EventMachine.stop
        end
      end
    end
  end

  it "should accept resolve to a ipv6 ip from an ipv4 google proxy" do
    nginx_run_server({address: "$http_x_origin_ip"}, timeout: 10) do
      EventMachine.run do
        sub = EventMachine::HttpRequest.new("#{nginx_address}/resolved").get(head: {"x-origin-ip" => "66.249.81.131", "x-forwarded-for" => "2003:45:442c:8b3c:f945:b364:241e:420a"})
        sub.callback do
          expect(sub).to be_http_status(200)
          expect(sub.response).to be === "2003:45:442c:8b3c:f945:b364:241e:420a"
          EventMachine.stop
        end
      end
    end
  end
end

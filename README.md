Usage: bugalyzer.sh <command> <args>
Commands:
  -o|--outbound-by-inbound <CallTrace> <inbound>                Given inbound call-handler id, get outbound call-handler id
  -r|--caller-by-inbound <CallTrace> <inbound>                  Given inbound call-handler id, get caller
  -e|--callee-by-inbound <CallTrace> <inbound>                  Given inbound call-handler id, get callee
  -i|--inbound-by-outbound <CallTrace> <outbound>               Given outbound call-handler id, get inbound call-handler id
  -s|--sip-by-inbound <CallTrace> <inbound>                     Given inbound call-handler id, get SIP call-id (or just call-id)
  -n|--next-sip-by-inbound <CallTrace> <inbound>                Given inbound call-handler id, get next SIP call-id (or just call-id)
  -x|--inbound-by-sip <CallTrace> <sip-id>                      Given SIP call-id (or just call-id), get inbound call-handler id
  -y|--outbound-by-sip <CallTrace> <sip-id>                     Given SIP call-id (or just call-id), get outbound call-handler id
  -z|--nextsip-by-sip <CallTrace> <sip-id>                      Given SIP call-id (or just call-id), get next SIP call-id (or just call-id)
  -m|--mp-by-outbound <Transactions log> <outbound>             Given outbound call-handler id, get MP
  -a|--all-call-handlers-ids <CallTrace>                        Get all inbound call-handlers ids
  -b|--all-call-handlers-ids-of-caller <CallTrace> <caller-ext>             Given caller extension, get all inbound call-handlers ids
  -q|--all <node1-folder> <node2-folder> <time-rounded> <caller-extension>  Given two folders (*), each containing at least CallTrace and CallStats
                                                                            logs, time (rounded to the hour only) and caller extension, this
                                                                            command will output all relevant info for this call, both textually
                                                                            and in HTML file.
                                                                            (*) Important: folders' names must begin with 4 letters node ID.

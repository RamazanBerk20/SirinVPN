package org.sirinvpn.client;
import org.sirinvpn.client.IResult;
import org.sirinvpn.client.IStatus;
interface IControl {
    String snapshot();
    void subscribe(IStatus listener);
    void unsubscribe(IStatus listener);
    void execute(String command, String arguments, String requestId, long generation, IResult result);
}

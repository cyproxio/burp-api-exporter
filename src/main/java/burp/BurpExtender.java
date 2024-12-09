package burp;

import api_parser.ApiFrame;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender  implements IBurpExtender,IContextMenuFactory{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    PrintWriter stdout;
    PrintWriter stderr;

    private String EXTENSION_NAME = "API Exporter";
    public  String VERSION_INFO = "1.0";
    public  String FRAME_TITLE = "API Exporter Panel";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();


        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName(EXTENSION_NAME+ " "+VERSION_INFO);
        callbacks.registerContextMenuFactory( this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

        // Menü öğeleri için liste oluştur
        List<JMenuItem> menuItems = new ArrayList<>();

        // Menü öğesi oluştur
        JMenuItem menuItem = new JMenuItem("Export API Docs");

        // Menü öğesi tıklama işlemi
        menuItem.addActionListener(e -> {
            IHttpRequestResponse[] requestResponseArray = invocation.getSelectedMessages();

            SwingUtilities.invokeLater(() -> {
                try {
                    // İstekleri listeye ekle
                    List<IHttpRequestResponse> reqList = new ArrayList<>();
                    for (IHttpRequestResponse requestResponse : requestResponseArray) {
                        reqList.add(requestResponse);
                    }


                    // Frame formunu başlat
                    ApiFrame frame = new ApiFrame(reqList.size(),this.stdout,this.stderr);

                    // Set Title to Viewer
                    frame.setTitle(FRAME_TITLE);

                   frame.setRequest(reqList,BurpExtender.this.callbacks);

                    // Show Viewer
                    frame.setVisible(true);


                } catch (Exception ex) {
                    // Hata ayıklama ve bildirim
                    StringWriter sw = new StringWriter();
                    PrintWriter pw = new PrintWriter(sw);
                    ex.printStackTrace(pw);
                    pw.flush();

                    String stackTrace = sw.toString();
                    stderr.println(stackTrace);

                    BurpExtender.this.callbacks.issueAlert(
                            "Some error happened. Please check Burp Extensions Errors tab. Message: " + ex.getMessage()
                    );
                }
            });
        });

        // Menü öğesini listeye ekle
        menuItems.add(menuItem);

        return menuItems;
    }
}

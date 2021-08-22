package fun.fireline.controller;

import com.jfoenix.controls.JFXButton;
import fun.fireline.core.Constants;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Window;
import org.apache.log4j.Logger;

import java.awt.*;
import java.io.IOException;
import java.net.*;
import java.util.HashMap;
import java.util.Map;

// OA页面相关逻辑
public class OAController{

    @FXML
    private VBox selectOAButton;      // 漏洞种类按钮
    @FXML
    private AnchorPane OA_content;     // 按钮对应的功能

    public static Map<String, Object> history = new HashMap<String, Object>();

    public static  Logger logger = Logger.getLogger(MainController.class);
    // 加载
    @FXML
    public void initialize() {

        // lambda 表达式获取 drawer 中的按钮，切换界面
        for (Node node: selectOAButton.getChildren()){
            if (node.getAccessibleText() != null){
                node.addEventHandler(MouseEvent.MOUSE_CLICKED, (e) -> {
                    refreshPage(node.getAccessibleText());
                });
            }
        }
        refreshPage("OA-Seeyon");
    }

    private void refreshPage(String page){
        try {
            this.OA_content.getChildren().clear();
            AnchorPane contentPage = FXMLLoader.load(getClass().getClassLoader().getResource("fxml/oa/" + page + ".fxml"));

            this.OA_content.getChildren().add(contentPage);
        } catch (IOException e) {
            logger.debug(e);
        }
    }


}
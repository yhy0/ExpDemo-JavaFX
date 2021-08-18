package fun.fireline;

import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import javafx.application.Application;
import javafx.stage.WindowEvent;

import javax.swing.*;
import java.net.URL;
import java.util.Objects;


public class AppStartUp extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception{
        Parent root = FXMLLoader.load(getClass().getClassLoader().getResource("fxml/Main.fxml"));
        primaryStage.setTitle("神机");
        primaryStage.setScene(new Scene(root));
        // 退出程序的时候，子线程也一起退出
        primaryStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
            @Override
            public void handle(WindowEvent event) {
                System.exit(0);
            }
        });
        //设置窗口不可拉伸
        primaryStage.setResizable(false);

        primaryStage.getIcons().add(new Image(getClass().getClassLoader().getResource("img/sec.png").toString()));

        primaryStage.show();
    }


    public static void main(String[] args) {
//        try {
//            URL iconURL = AppStartUp.class.getClassLoader().getResource("img/sec.png");
//            java.awt.Image image = new ImageIcon(iconURL).getImage();
//            com.apple.eawt.Application.getApplication().setDockIconImage(image);
//        } catch (Exception e) {
//            // Won't work on Windows or Linux.
//        }

        launch(args);
    }
}
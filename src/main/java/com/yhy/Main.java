package com.yhy;

import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;


public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        try {
            ClassLoader classLoader = getClass().getClassLoader();
            Parent root = FXMLLoader.load(classLoader.getResource("sample.fxml"));

            primaryStage.setTitle("图形化漏洞利用Demo-JavaFx版");

            primaryStage.getIcons().add(new Image(String.valueOf(classLoader.getResource("sec.png"))));

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

            primaryStage.show();
        } catch (Exception e) {
            System.out.println(e);
        }

    }

}


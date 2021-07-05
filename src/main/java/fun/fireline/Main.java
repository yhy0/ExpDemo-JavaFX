package fun.fireline;

import com.sun.deploy.uitoolkit.impl.fx.HostServicesFactory;
import com.sun.javafx.application.HostServicesDelegate;
import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import java.util.Objects;


public class Main extends Application {
    @Override
    public void start(Stage primaryStage) throws Exception {
        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getClassLoader().getResource("fxml/Main.fxml")));

//        primaryStage.getIcons().add(new Image(this.getClass().getResourceAsStream("sicadcam.png")));
        primaryStage.setTitle("图形化漏洞利用Demo-JavaFx版");

        primaryStage.getIcons().add(new Image(Objects.requireNonNull(getClass().getClassLoader().getResource("img/sec.png")).toString()));

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

    }

    public static void main(String[] args) {
        launch(args);
    }
}

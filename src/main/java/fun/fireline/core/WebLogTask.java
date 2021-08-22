package fun.fireline.core;

/**
 * @author yhy
 * @date 2021/8/21 14:18
 * @github https://github.com/yhy0
 */

import javafx.concurrent.Task;

public class WebLogTask extends Task<Void> {
    private String result;
    private final String target;
    private final String path;
    private final String year;
    private final String mouth;
    private final String day;

    public WebLogTask(String target, String path, String year, String mouth, String day) {
        this.path = path;
        this.target = target;
        this.year = year;
        this.mouth = mouth;
        this.day = day;
    }

    protected Void call() {
        String result = LogAnalysis.logAnalysis(this.target, this.path, this.year, this.mouth, this.day);
        this.updateMessage(result);
        this.setResult(result);
        return null;
    }

    public String getResult() {
        return this.result;
    }

    public void setResult(String result) {
        this.result = result;
    }
}


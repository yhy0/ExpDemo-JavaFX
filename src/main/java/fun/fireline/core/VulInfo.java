package fun.fireline.core;

import javafx.beans.property.SimpleStringProperty;

/**
 * @author yhy
 * @date 2021/3/26 16:53
 * @github https://github.com/yhy0
 * 映射批量检查界面中的表格，信息基本类
 */

public class VulInfo {
    private final SimpleStringProperty id = new SimpleStringProperty();
    private final SimpleStringProperty target = new SimpleStringProperty();
    private final SimpleStringProperty isVul = new SimpleStringProperty();

    public VulInfo(String id, String target, String isVul) {
        setId(id);
        setTarget(target);
        setIsVul(isVul);
    }

    public String getId() {
        return id.get();
    }

    public void setId(String id) {
        this.id.set(id);
    }

    public String getTarget() {
        return target.get();
    }

    public void setTarget(String target) {
        this.target.set(target);
    }

    public String getIsVul() {
        return isVul.get();
    }

    public void setIsVul(String isVul) {
        this.isVul.set(isVul);
    }

    @Override
    public String toString() {
        return "VulInfo{" +
                "id=" + id +
                ", target=" + target +
                ", isVul=" + isVul +
                '}';
    }
}

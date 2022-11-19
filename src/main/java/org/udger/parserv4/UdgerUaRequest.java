/*
  UdgerParser - Java agent string parser based on Udger https://udger.com/products/local_parser

  author     The Udger.com Team (info@udger.com)
  copyright  Copyright (c) Udger s.r.o.
  license    GNU Lesser General Public License
  link       https://udger.com/products
*/
package org.udger.parserv4;

import java.io.Serializable;
import java.util.Map;

/**
 * The Class UdgerUaRequest.
 */
public class UdgerUaRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    public static class Builder {
        private String uaString;
        private String secChUa;
        private String secChUaFullVersionList;
        private String secChUaMobile;
        private String secChUaFullVersion;
        private String secChUaPlatform;
        private String secChUaPlatformVersion;
        private String secChUaModel;
        private String headers;

        public Builder withUaString(String uaString) {
            this.uaString = uaString;
            return this;
        }
        public Builder withSecChUa(String secChUa) {
            this.secChUa = secChUa;
            return this;
        }
        public Builder withSecChUaFullVersionList(String secChUaFullVersionList) {
            this.secChUaFullVersionList = secChUaFullVersionList;
            return this;
        }
        public Builder withSecChUaMobile(String secChUaMobile) {
            this.secChUaMobile = secChUaMobile;
            return this;
        }
        public Builder withSecChUaFullVersion(String secChUaFullVersion) {
            this.secChUaFullVersion = secChUaFullVersion;
            return this;
        }
        public Builder withSecChUaPlatform(String secChUaPlatform) {
            this.secChUaPlatform = secChUaPlatform;
            return this;
        }
        public Builder withSecChUaPlatformVersion(String secChUaPlatformVersion) {
            this.secChUaPlatformVersion = secChUaPlatformVersion;
            return this;
        }
        public Builder withSecChUaModel(String secChUaModel) {
            this.secChUaModel = secChUaModel;
            return this;
        }
        public Builder fromHeaders(String headers) {
           this.headers = headers;
           return this;
        }

        public UdgerUaRequest build() {
            UdgerUaRequest result = new UdgerUaRequest();
            result.setSecChUa(secChUa);
            result.setUaString(this.uaString);
            result.setSecChUaFullVersionList(this.secChUaFullVersionList);
            result.setSecChUaMobile(this.secChUaMobile);
            result.setSecChUaFullVersion(this.secChUaFullVersion);
            result.setSecChUaPlatform(this.secChUaPlatform);
            result.setSecChUaPlatformVersion(this.secChUaPlatformVersion);
            result.setSecChUaModel(this.secChUaModel);
            if (StringUtils.isNotEmpty(headers)) {
                result.setFromHeaders(headers);
            }
            return result;
        }
    }
    private String uaString;
    private String secChUa;
    private String secChUaFullVersionList;
    private String secChUaMobile;
    private String secChUaFullVersion;
    private String secChUaPlatform;
    private String secChUaPlatformVersion;
    private String secChUaModel;

    public String getUaString() {
        return uaString;
    }
    public void setUaString(String uaString) {
        this.uaString = uaString;
    }
    public String getSecChUa() {
        return secChUa;
    }
    public void setSecChUa(String secChUa) {
        this.secChUa = secChUa;
    }
    public String getSecChUaFullVersionList() {
        return secChUaFullVersionList;
    }
    public void setSecChUaFullVersionList(String secChUaFullVersionList) {
        this.secChUaFullVersionList = secChUaFullVersionList;
    }
    public String getSecChUaMobile() {
        return secChUaMobile;
    }
    public void setSecChUaMobile(String secChUaMobile) {
        this.secChUaMobile = secChUaMobile;
    }
    public String getSecChUaFullVersion() {
        return secChUaFullVersion;
    }
    public void setSecChUaFullVersion(String secChUaFullVersion) {
        this.secChUaFullVersion = secChUaFullVersion;
    }
    public String getSecChUaPlatform() {
        return secChUaPlatform;
    }
    public void setSecChUaPlatform(String secChUaPlatform) {
        this.secChUaPlatform = secChUaPlatform;
    }
    public String getSecChUaPlatformVersion() {
        return secChUaPlatformVersion;
    }
    public void setSecChUaPlatformVersion(String secChUaPlatformVersion) {
        this.secChUaPlatformVersion = secChUaPlatformVersion;
    }
    public String getSecChUaModel() {
        return secChUaModel;
    }
    public void setSecChUaModel(String secChUaModel) {
        this.secChUaModel = secChUaModel;
    }

    public static UdgerUaRequest fromHeaders(Map<String, String> headers) {
        UdgerUaRequest udgerUaRequest = new UdgerUaRequest();
        udgerUaRequest.setSecChUa(headers.get("sec-ch-ua"));
        udgerUaRequest.setSecChUaFullVersionList(headers.get("sec-ch-ua-full-version-list"));
        udgerUaRequest.setSecChUaMobile(headers.get("sec-ch-ua-mobile"));
        udgerUaRequest.setSecChUaFullVersion(headers.get("sec-ch-ua-full-version"));
        udgerUaRequest.setSecChUaPlatform(headers.get("sec-ch-ua-platform"));
        udgerUaRequest.setSecChUaPlatformVersion(headers.get("sec-ch-ua-platform-version"));
        udgerUaRequest.setSecChUaModel(headers.get("sec-ch-ua-model"));
        udgerUaRequest.setUaString(headers.get("user-agent"));
        return udgerUaRequest;
    }

    private void setFromHeaders(String headers) {
        if (headers != null) {
            String[] fields = headers.split("\\R");
            for (String field : fields) {
                String[] nameVal = field.split(":");
                if (nameVal.length == 2) {
                    String name = nameVal[0].toLowerCase();
                    String value = nameVal[1];
                    if ("sec-ch-ua".equals(name)) {
                        setSecChUa(value);
                    } else if ("sec-ch-ua-full-version-list".equals(name)) {
                        setSecChUaFullVersionList(value);
                    } else if ("sec-ch-ua-mobile".equals(name)) {
                        setSecChUaMobile(value);
                    } else if ("sec-ch-ua-full-version".equals(name)) {
                        setSecChUaFullVersion(value);
                    } else if ("sec-ch-ua-platform".equals(name)) {
                        setSecChUaPlatform(value);
                    } else if ("sec-ch-ua-platform-version".equals(name)) {
                        setSecChUaPlatformVersion(value);
                    } else if ("sec-ch-ua-model".equals(name)) {
                        setSecChUaModel(value);
                    } else if ("user-agent".equals(name)) {
                        setUaString(value);
                    }
                }
            }
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((uaString == null) ? 0 : uaString.hashCode());
        result = prime * result + ((secChUa == null) ? 0 : secChUa.hashCode());
        result = prime * result + ((secChUaFullVersionList == null) ? 0 : secChUaFullVersionList.hashCode());
        result = prime * result + ((secChUaMobile == null) ? 0 : secChUaMobile.hashCode());
        result = prime * result + ((secChUaFullVersion == null) ? 0 : secChUaFullVersion.hashCode());
        result = prime * result + ((secChUaPlatform == null) ? 0 : secChUaPlatform.hashCode());
        result = prime * result + ((secChUaPlatformVersion == null) ? 0 : secChUaPlatformVersion.hashCode());
        result = prime * result + ((secChUaModel == null) ? 0 : secChUaModel.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        UdgerUaRequest other = (UdgerUaRequest) obj;
        if (uaString == null) {
            if (other.uaString != null)
                return false;
        } else if (!uaString.equals(other.uaString))
            return false;
        if (secChUa == null) {
            if (other.secChUa != null)
                return false;
        } else if (!secChUa.equals(other.secChUa))
            return false;
        if (secChUaFullVersionList == null) {
            if (other.secChUaFullVersionList != null)
                return false;
        } else if (!secChUaFullVersionList.equals(other.secChUaFullVersionList))
            return false;
        if (secChUaMobile == null) {
            if (other.secChUaMobile != null)
                return false;
        } else if (!secChUaMobile.equals(other.secChUaMobile))
            return false;
        if (secChUaFullVersion == null) {
            if (other.secChUaFullVersion != null)
                return false;
        } else if (!secChUaFullVersion.equals(other.secChUaFullVersion))
            return false;
        if (secChUaPlatform == null) {
            if (other.secChUaPlatform != null)
                return false;
        } else if (!secChUaPlatform.equals(other.secChUaPlatform))
            return false;
        if (secChUaPlatformVersion == null) {
            if (other.secChUaPlatformVersion != null)
                return false;
        } else if (!secChUaPlatformVersion.equals(other.secChUaPlatformVersion))
            return false;
        if (secChUaModel == null) {
            if (other.secChUaModel != null)
                return false;
        } else if (!secChUaModel.equals(other.secChUaModel))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "UdgerUaRequest [" +
                "uaString=" + uaString +
                ", secChUa=" + secChUa +
                ", secChUaFullVersionList=" + secChUaFullVersionList +
                ", secChUaMobile=" + secChUaMobile +
                ", secChUaFullVersion=" + secChUaFullVersion +
                ", secChUaPlatform=" + secChUaPlatform +
                ", secChUaPlatformVersion=" + secChUaPlatformVersion +
                ", secChUaModel=" + secChUaModel +
                "]";
    }

}

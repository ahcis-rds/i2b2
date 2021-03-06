//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.1.2-b01-fcs 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2008.05.29 at 01:45:52 PM EDT 
//


package edu.harvard.i2b2.fr.datavo.pm;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for configureType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="configureType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="environment" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="helpURL" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="user" type="{http://www.i2b2.org/xsd/cell/pm/1.1/}userType"/>
 *         &lt;element name="cell_datas" type="{http://www.i2b2.org/xsd/cell/pm/1.1/}cell_datasType"/>
 *         &lt;element name="global_data" type="{http://www.i2b2.org/xsd/cell/pm/1.1/}global_dataType"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "configureType", propOrder = {
    "environment",
    "helpURL",
    "user",
    "cellDatas",
    "globalData"
})
public class ConfigureType {

    @XmlElement(required = true)
    protected String environment;
    @XmlElement(required = true)
    protected String helpURL;
    @XmlElement(required = true)
    protected UserType user;
    @XmlElement(name = "cell_datas", required = true)
    protected CellDatasType cellDatas;
    @XmlElement(name = "global_data", required = true)
    protected GlobalDataType globalData;

    /**
     * Gets the value of the environment property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEnvironment() {
        return environment;
    }

    /**
     * Sets the value of the environment property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEnvironment(String value) {
        this.environment = value;
    }

    /**
     * Gets the value of the helpURL property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getHelpURL() {
        return helpURL;
    }

    /**
     * Sets the value of the helpURL property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setHelpURL(String value) {
        this.helpURL = value;
    }

    /**
     * Gets the value of the user property.
     * 
     * @return
     *     possible object is
     *     {@link UserType }
     *     
     */
    public UserType getUser() {
        return user;
    }

    /**
     * Sets the value of the user property.
     * 
     * @param value
     *     allowed object is
     *     {@link UserType }
     *     
     */
    public void setUser(UserType value) {
        this.user = value;
    }

    /**
     * Gets the value of the cellDatas property.
     * 
     * @return
     *     possible object is
     *     {@link CellDatasType }
     *     
     */
    public CellDatasType getCellDatas() {
        return cellDatas;
    }

    /**
     * Sets the value of the cellDatas property.
     * 
     * @param value
     *     allowed object is
     *     {@link CellDatasType }
     *     
     */
    public void setCellDatas(CellDatasType value) {
        this.cellDatas = value;
    }

    /**
     * Gets the value of the globalData property.
     * 
     * @return
     *     possible object is
     *     {@link GlobalDataType }
     *     
     */
    public GlobalDataType getGlobalData() {
        return globalData;
    }

    /**
     * Sets the value of the globalData property.
     * 
     * @param value
     *     allowed object is
     *     {@link GlobalDataType }
     *     
     */
    public void setGlobalData(GlobalDataType value) {
        this.globalData = value;
    }

}

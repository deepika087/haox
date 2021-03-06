package org.apache.haox.asn1.type;

import org.apache.haox.asn1.EncodingOption;
import org.apache.haox.asn1.LimitedByteBuffer;
import org.apache.haox.asn1.TagClass;
import org.apache.haox.asn1.TaggingOption;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * For collection type that may consist of tagged fields
 */
public abstract class Asn1CollectionType extends AbstractAsn1Type<Asn1CollectionType> {
    private Asn1FieldInfo[] fieldInfos;
    private Asn1Type[] fields;

    public Asn1CollectionType(int universalTagNo, Asn1FieldInfo[] fieldInfos) {
        super(TagClass.UNIVERSAL, universalTagNo);
        setValue(this);
        this.fieldInfos = fieldInfos;
        this.fields = new Asn1Type[fieldInfos.length];
        setEncodingOption(EncodingOption.CONSTRUCTED);
    }

    @Override
    public boolean isConstructed() {
        return true;
    }

    @Override
    protected int encodingBodyLength() {
        int allLen = 0;
        AbstractAsn1Type field;
        TaggingOption taggingOption;
        for (int i = 0; i < fields.length; ++i) {
            field = (AbstractAsn1Type) fields[i];
            if (field != null) {
                if (fieldInfos[i].isTagged()) {
                    taggingOption = fieldInfos[i].getTaggingOption();
                    allLen += field.taggedEncodingLength(taggingOption);
                } else {
                    allLen += field.encodingLength();
                }
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        Asn1Type field;
        TaggingOption taggingOption;
        for (int i = 0; i < fields.length; ++i) {
            field = fields[i];
            if (field != null) {
                if (fieldInfos[i].isTagged()) {
                    taggingOption = fieldInfos[i].getTaggingOption();
                    field.taggedEncode(buffer, taggingOption);
                } else {
                    field.encode(buffer);
                }
            }
        }
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        initFields();

        Asn1Collection coll = createCollection();
        coll.decode(tagFlags(), tagNo(), content);

        int lastPos = -1, foundPos = -1;
        for (Asn1Item item : coll.getValue()) {
            foundPos = -1;
            for (int i = lastPos + 1; i < fieldInfos.length; ++i) {
                if (item.isContextSpecific()) {
                    if(fieldInfos[i].getTagNo() == item.tagNo()) {
                        foundPos = i;
                        break;
                    }
                } else if (fields[i].tagFlags() == item.tagFlags() &&
                        fields[i].tagNo() == item.tagNo()) {
                    foundPos = i;
                    break;
                }
            }
            if (foundPos == -1) {
                throw new RuntimeException("Unexpected item with (tagFlags, tagNo): ("
                        + item.tagFlags() + ", " + item.tagNo() + ")");
            }

            if (! item.isFullyDecoded()) {
                AbstractAsn1Type fieldValue = (AbstractAsn1Type) fields[foundPos];
                if (item.isContextSpecific()) {
                    item.decodeValueWith(fieldValue, fieldInfos[foundPos].getTaggingOption());
                } else {
                    item.decodeValueWith(fieldValue);
                }
            }
            fields[foundPos] = item.getValue();
            lastPos = foundPos;
        }
    }

    private void initFields() {
        for (int i = 0; i < fieldInfos.length; ++i) {
            try {
                fields[i] = fieldInfos[i].getType().newInstance();
            } catch (Exception e) {
                throw new IllegalArgumentException("Bad field info specified at index of " + i, e);
            }
        }
    }

    protected abstract Asn1Collection createCollection();

    protected <T extends Asn1Type> T getFieldAs(int index, Class<T> t) {
        Asn1Type value = fields[index];
        if (value == null) return null;
        return (T) value;
    }

    protected void setFieldAs(int index, Asn1Type value) {
        fields[index] = value;
    }

    protected String getFieldAsString(int index) {
        Asn1Type value = fields[index];
        if (value == null) return null;

        if (value instanceof Asn1String) {
            return ((Asn1String) value).getValue();
        }

        throw new RuntimeException("The targeted field type isn't of string");
    }

    protected byte[] getFieldAsOctets(int index) {
        Asn1OctetString value = getFieldAs(index, Asn1OctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    protected void setFieldAsOctets(int index, byte[] bytes) {
        Asn1OctetString value = new Asn1OctetString(bytes);
        setFieldAs(index, value);
    }

    protected Integer getFieldAsInteger(int index) {
        Asn1Integer value = getFieldAs(index, Asn1Integer.class);
        if (value != null) {
            return value.getValue();
        }
        return null;
    }

    protected void setFieldAsInt(int index, int value) {
        setFieldAs(index, new Asn1Integer(value));
    }

    protected Asn1Type getFieldAsAny(int index) {
        Asn1Any any = getFieldAs(index, Asn1Any.class);
        if (any != null) {
            return any.getValue();
        }
        return null;
    }

    protected void setFieldAsAny(int index, Asn1Type value) {
        if (value != null) {
            setFieldAs(index, new Asn1Any(value));
        }
    }
}

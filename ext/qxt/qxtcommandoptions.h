
/****************************************************************************
** Copyright (c) 2006 - 2011, the LibQxt project.
** See the Qxt AUTHORS file for a list of authors and copyright holders.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the LibQxt project nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
** <http://libqxt.org>  <foundation@libqxt.org>
*****************************************************************************/

#ifndef QXTCOMMANDOPTIONS_H
#define QXTCOMMANDOPTIONS_H
#include <qxtglobal.h>
#include <QStringList>
#include <QVariant>
#include <QCoreApplication>     // for Q_DECLARE_TR_FUNCTIONS
#include <QMultiHash>
#include <QFlags>
class QxtCommandOptionsPrivate;
QT_FORWARD_DECLARE_CLASS(QTextStream)
QT_FORWARD_DECLARE_CLASS(QIODevice)


class QXT_CORE_EXPORT QxtCommandOptions
{
    Q_DECLARE_TR_FUNCTIONS(QxtCommandOptions)

public:
    /*!
     * \enum QxtCommandOptions::FlagStyle
     * This enum type defines which type of option prefix is used.
     * Slash is the default on Windows.
     * DoubleDash is the default on all other platforms.
     */
    enum FlagStyle
    {
        DoubleDash,         /*!< Two dashes (GNU-style) */
        SingleDash,         /*!< One dash (UNIX-style) */
        Slash               /*!< Forward slash (Windows-style) */
    };
    /*!
     * \enum QxtCommandOptions::ParamStyle
     * This enum type defines what syntax is used for options that
     * require parameters. Equals is the default on Windows.
     * SpaceAndEquals is the default on all other platforms.
     */
    enum ParamStyle
    {
        Space = 1,          /*!< Space ("-option value") */
        Equals = 2,         /*!< Equals sign ("/option=value") */
        SpaceAndEquals = 3  /*!< Accept either */
    };
    /*!
     * \enum QxtCommandOptions::ParamType
     * \flags QxtCommandOptions::ParamTypes
     * This enum type is used to specify flags that control the
     * interpretation of an option.
     *
     * The ParamTypes type is a typedef for QFlags<ParamType>. It stores
     * an OR combination of ParamType values.
     */
    enum ParamType
    {
        NoValue = 0,                /*!< The option does not accept a value. */
        ValueOptional = 1,          /*!< The option may accept a value. */
        ValueRequired = 2,          /*!< The option requires a value. */
        Optional = ValueOptional,   /*!< The option may accept a value. Deprecated in favor of ValueOptional. */
        Required = ValueRequired,   /*!< The option requires a value. Deprecated in favor of ValueRequired. */
        AllowMultiple = 4,          /*!< The option may be passed multiple times. */
        Undocumented = 8            /*!< The option is not output in the help text. */
    };
    Q_DECLARE_FLAGS(ParamTypes, ParamType)

    QxtCommandOptions();

    void setFlagStyle(FlagStyle style);
    FlagStyle flagStyle() const;
    void setParamStyle(ParamStyle style);
    ParamStyle paramStyle() const;
    void setScreenWidth(quint16 width);
    quint16 screenWidth() const;

    void addSection(const QString& name);
    void add(const QString& name, const QString& desc = QString(), ParamTypes paramType = NoValue, int group = -1);
    void alias(const QString& from, const QString& to);

    QStringList positional() const;
    QStringList unrecognized() const;
    int count(const QString& name) const;
    QVariant value(const QString& name) const;
    QMultiHash<QString, QVariant> parameters() const;

    void parse(int argc, char** argv);
    void parse(QStringList params);

    void showUsage(bool showQtOptions = false, QIODevice* device = 0) const;
    void showUsage(bool showQtOptions, QTextStream& stream) const;
    QString getUsage(bool showQtOptions = false) const;

    bool showUnrecognizedWarning(QIODevice* device = 0) const;
    bool showUnrecognizedWarning(QTextStream& stream) const;
    QString getUnrecognizedWarning() const;

private:
    QXT_DECLARE_PRIVATE(QxtCommandOptions)
};
Q_DECLARE_OPERATORS_FOR_FLAGS(QxtCommandOptions::ParamTypes)

#endif // QXTCOMMANDOPTIONS_H

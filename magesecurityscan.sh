#/bin/bash
WORKINGDIR='magesecurityscan'

#Input Validation
if [  -z $1 ] || [ -z $2 ]
then
  DIE=1
else
  SCANPATH=$1
  if [ ! -e $SCANPATH ]
  then
    DIE=1
    MESSAGE='Path not found'
  fi
  RULES=$2
  if [ ! -e $RULES ]
  then
    DIE=1
    MESSAGE='Rules file not found'
  fi
fi

if [ ! -z $3 ]
then
  if [ "$3" != "standard" ] && [ "$3" != "deep" ] && [ "$3" != "fast" ]
  then
    DIE=1
    MESSAGE="Invalid scan type specified"
  else
    SCANTYPE=$3
  fi
else
  SCANTYPE='standard'
fi

if [ ! -z $4 ]
then
  if [ "$4" != "code" ] && [ "$4" != "all" ]
  then
    DIE=1
    MESSAGE="Invalid scan precision specified"
  else
    PRECISION=$4
  fi
else
  if [ "$SCANTYPE" = 'deep' ]
  then
    PRECISION='all'
  else
    PRECISION='code'
  fi
fi

if [ ! -z $5 ]
then
  if [ "$5" != "hash" ] && [ "$5" != "size" ] && [ "$5" != "none" ]
  then
    DIE=1
    MESSAGE="Invalid whitelist option specified"
  else
    WHITELIST=$5
  fi
else
  if [ "$SCANTYPE" = 'fast' ]
  then
    WHITELIST='size'
  else
    WHITELIST='hash'
  fi
fi

if [ $DIE ]
then
  echo 'Usage: ./magescecurityscan.sh <path to scan> <rules file> [<scan type>fast|standard|deep] [<scan precision> all|code] [<whitelist option> hash|size|none]'
  echo $MESSAGE
  exit 0
fi
#End Input Validation

#Checking YARA Instalation
YARA=`which yara`
if [ ! -n "$YARA" ]
then
  echo "The yara package has not been found. For the best scanning results it is recommended that yara should be installed. Defaulting to grep for pattern matching using rules.txt"
fi

#Setting Scan Options
if [ $PRECISION == 'code' ]
then
  if [ $WHITELIST == 'size' ]
  then
    find $SCANPATH -type f \( -iname \*.php -o -iname \*.js  -o -iname \*.phtml -o -iname \*.html \) -printf "%s %p\n" > $WORKINGDIR/scanlist
  elif [ $WHITELIST == 'hash' ]
  then
    find $SCANPATH -type f \( -iname \*.php -o -iname \*.js  -o -iname \*.phtml -o -iname \*.html \) -exec sha1sum {} \; > $WORKINGDIR/scanlist
  else
    find $SCANPATH -type f \( -iname \*.php -o -iname \*.js  -o -iname \*.phtml -o -iname \*.html \) > $WORKINGDIR/scanlist
  fi
else
  if [ $WHITELIST == 'size' ]
  then
    find $SCANPATH -type f  -printf "%s %p\n" > $WORKINGDIR/scanlist
  elif [ $WHITELIST == 'hash' ]
  then
    find $SCANPATH -type f -exec sha1sum {} \; > $WORKINGDIR/scanlist
  else
    find $SCANPATH -type f > $WORKINGDIR/scanlist
  fi
fi
#End Setting Scan Options

#Process files to be whitelisted
if [ $WHITELIST != 'none' ]
then
  php whitelistprocessor.php scanlist $WHITELIST $WORKINGDIR
fi

SCANFILE="$WORKINGDIR/scanlist"
while IFS= read -r line
do
  if [ -e "$line" ]
  then
    if [ ! -n "$YARA" ]
    then
      grep -H -F -f rules.txt "$line"
    else
      result=`yara -s $RULES "$line"`
      if [ -n "$result" ]
      then
        echo $result | tr '\n' ' '
        echo ' '
      fi
    fi
  fi
done <"$SCANFILE"

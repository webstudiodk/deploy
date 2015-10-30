<?php

/**
 * Class OTT
 * Generate One Time Token
 */
class OTT {

    //Default hash method
    
    const DEFAULT_HASH = "sha1";
    
    const SSL = "0";

    //Default value for how long the code will be valid (in seconds)
    
    const DEFAULT_EXPIRATION = 300;

    //Default value for the number of digits in the code
    
    const DEFAULT_DIGITSNR = 6;


    protected $doubleDigits = array (0 => "0", 1 => "2", 2 => "4", 3 => "6", 4 => "8", 5 => "1", 6 => "3", 7 => "5", 8 => "7", 9 => "9" );

    // Digit's power ... @var array
    protected $DIGITS_POWER = array (0=>"1", 1=>"10", 2=>"100", 3=>"1000", 4=>"10000", 5=>"100000", 6=>"1000000", 7=>"10000000", 8=>"100000000", 9=>"1000000000");

    //the secret key ... @var string
    protected $secretKey;

    //Time of execution ... @var long
    protected $time;

    //The expiration time of the code ... @var long
    protected $expiration;

    //The number of digits in the code ... @var int
    protected $codeDigitsNr;

    //Flag to add or not a checksum at the end of the code ... @var bool
    protected $addChecksum = false;

    //Truncation offset ...@var int
    protected $truncationOffset = 15;

    //Generated code ... @var string
    protected $generatedCode;

    //Constructor ... @param string $secretKey - the secret key
    public function __construct($secretKey = false, $expiration = false, $digits = false)
    {
        $this->time = time();
        $this->setSecretKey($secretKey);
        $this->setExpirationTime($expiration);
        $this->setDigitsNumber($digits);
    }

    //Returns the timestamp used for creating the code ... @return long
    //time is used 
    public function getTimeUsedInGeneration ()
    {
        return $this->time;
    }

    //Get the generated code ... @return string
    public function getGeneratedCode ()
    {
        return $this->generatedCode;
    }

    // Set the secret key
    // @param string $secretKey - the secret key
    // @return bool

    public function setSecretKey ($secretKey)
    {
        if ($secretKey)
        {
            $this->secretKey = $secretKey;
            return true;
        }
        else
        {
            return false;
        }
    }

    // @param int $expiration
    // @return bool

    public function setExpirationTime ($expiration = self::DEFAULT_EXPIRATION)
    {
        $expiration = (int)$expiration;
        if ($expiration > 0)
        {
            $this->expiration = $expiration;
            return true;
        } else
        {
            $this->expiration = self::DEFAULT_EXPIRATION;
            return false;
        }
    }

    // Get the expiration time of the password
    // @return int

    public function getExpirationTime ()
    {
        return $this->expiration;
    }


    // Set the truncation offset
    // @param int $truncationOffset
    // @return bool

    public function setTruncationOffset ($truncationOffset)
    {
        $truncationOffset = (int)$truncationOffset;

        if ($truncationOffset > 0)
        {
            $this->truncationOffset = $truncationOffset;
            return true;
        }
        else
        {
            return false;
        }
    }

    // Set if it should add or not a checksum at the end of the code
    // @param bool $addChecksum

    public function addChecksum ($addChecksum = false)
    {
        $this->addChecksum = (bool)$addChecksum;
    }

    // Calculate the checksum of a result
    // @param int $num - number
    // @param int $digits - number of digits
    // @return int

    public function calcChecksum($num, $digits)
    {
        $doubleDigit = true;
        $total = 0;
        while ($digits-- > 0)
        {
            $digit = (int)($num%10);
            $num /= 10;
            if ($doubleDigit)
            {
                $digit = $this->doubleDigits[$digit];
            }
            $total += $digit;
            $doubleDigit = !$doubleDigit;
        }
        return 10 - $total%10;
    }


    // Generate a keyed hash value using the HMAC method
    // @param string $data - data to be hashed
    // @param string $hashFunct - hash function to be used
    // @param bool $rawOutput - if the output should be binary data or hex
    // @return string

    private function hmac($data, $hashFunct = self::DEFAULT_HASH, $rawOutput = false)
    {

        if (!in_array($hashFunct, hash_algos()))
        {
            $hashFunct = self::DEFAULT_HASH;
        }

        return hash_hmac($hashFunct, $data, $this->secretKey, $rawOutput);
    }

    // Calculate the one time password
    // @param int $movingFactor
    // @return string

    protected function calcOTT($movingFactor)
    {

        $movingFactor = str_pad($movingFactor, 16, "0", STR_PAD_LEFT);

        $digits = $this->addChecksum ? ($this->codeDigitsNr + 1) : $this->codeDigitsNr;
        $text = "";
        for($i = 7; $i >= 0; $i--)
        {
            $text .= ($movingFactor & 0xff);
            $movingFactor >>= 8;
        }

        $hash = $this->hmac($text);
        $hashLenght = strlen($hash);

        if ((0 <= $this->truncationOffset) && ($this->truncationOffset < ($hashLenght-4)))
        {
            $offset = $this->truncationOffset;
        }
        else
        {
            $offset = ord($hash[$hashLenght-1]) & 0xf;
        }

        for($i=0; $i<$hashLenght; $i++)
        {
            $hash[$i] = ord($hash[$i]);
        }
        $binary = (($hash[$offset] & 0x7f) << 24) | (($hash[$offset+1] & 0xff) << 16) | (($hash[$offset+2] & 0xff) << 8) | ($hash[$offset+3] & 0xff);

        $otp = $binary % $this->DIGITS_POWER[$this->codeDigitsNr];
        if ($this->addChecksum)
        {
            $otp = ($otp * 10) + $this->calcChecksum($otp, $this->codeDigitsNr);
        }

        $result = $otp;
        while (strlen($result) < $digits)
        {
            $result = "0".$result;
        }
        $this->generatedCode = $result;
        return $this->generatedCode;
    }

    // Generate a new code
    // @param int $truncationOffset
    // @return string

    public function generateCode ()
    {
        return $this->calcOTT($this->time/$this->expiration);
    }

    // Validate code
    // @param string $code
    // @return bool

    public function validateCode ($code)
    {
        if ($code == $this->calcOTT($this->time/$this->expiration))
        {
            return true;
        }
        else
        {
            $movingFactor = ($this->time-floor($this->expiration/(2)))/$this->expiration;
            return ($code == $this->calcOTT($movingFactor));
        }
    }
}
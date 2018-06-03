<?php

/*******************************************************************
 * The calling script will instantiate a new Http_log_parser       *
 * object and call the get_stats method on that object. The method *
 * will return an array containing various statistics that can be  *
 * outputted according to the calling script's needs.              *
 *******************************************************************
 *
 * Example code:
 * 
 * require('http_log_parser.php');
 * $log_parser = new Http_log_parser;
 * $stats = $log_parser->get_stats(%%LOG_NAME%%); // replace %%LOG_NAME%% with filename of log to be parsed
 * 
 * *****************************************************************/

class Http_log_parser {

    private $bad_lines = 0;
    private $file_pointer;
    private $parsed_log = array();

    public function get_stats($filename) {
        $this->parse_log_file($filename);
        $data = array(
            'count' => array ('total_count' => 0, 'error' => 0, 'error_pct' => 0, 'success' => 0, 'success_pct' => 0),
            'files' => array(),
            'referers' => array()
        );

        if ($data['count']['total_count'] = count($this->parsed_log)) { // total_count is greater than 0
            foreach ($this->parsed_log as $p) {
                // error vs success
                if (substr($p['status'],0,1)==2) { // specifies that only 2xx status codes are considered successful
                    $data['count']['success']++;
                } else {
                    $data['count']['error']++;
                }
                // files
                if (count($data['files'])) {
                    $found = array_search($p['path'],array_column($data['files'], 'path'));
                    if ($found !== false) {
                        $data['files'][$found]['visits']++;
                    } else {
                        $data['files'][] = array('path' => $p['path'], 'visits' => 1);
                    }
                } else {
                    $data['files'][0] = array('path' => $p['path'], 'visits' => 1);
                }
                // referers
                if (count($data['referers'])) {
                    $found = array_search($p['referer'],array_column($data['referers'], 'referer'));
                    if ($found !== false) {
                        $data['referers'][$found]['requests']++;
                    } else {
                        $data['referers'][] = array('referer' => $p['referer'], 'requests' => 1);
                    }
                } else {
                    $data['referers'][0] = array('referer' => $p['referer'], 'requests' => 1);
                }
            }
            $data['count']['error_pct'] = number_format($data['count']['error'] * 100 / $data['count']['total_count'],3);
            $data['count']['success_pct'] = number_format($data['count']['success'] * 100 / $data['count']['total_count'],3);
            for ($i=0;$i<count($data['files']);$i++) {
                $data['files'][$i]['visited_pct'] = number_format($data['files'][$i]['visits'] * 100 / $data['count']['total_count'],3);
            }
            for ($i=0;$i<count($data['referers']);$i++) {
                $data['referers'][$i]['request_pct'] = number_format($data['referers'][$i]['requests'] * 100 / $data['count']['total_count'],3);
            }

    /* 
    Good vs. malicious user-agent counts could easily be added to this function by identifying a dataset of recognized "good" versus "malicious" 
    agents and running counts similar to the "files" and "referers" routines provided above. We might also identify malicious agents based upon 
    repeated requests for the same files over a given period of time. 
    */

            return $data;
        } else { // no data in file
            return "Log file was empty or unreadable.";
        }
    }

    private function parse_log_file($filename) {
        if (!is_readable($filename) || !$this->open_log($filename)) {
            return 'Unable to read file.';
        }
        while ($line = $this->read_line()) {
            $this->parsed_log[] = $this->parse_line($line);
        }
        $this->close_log();
        return true;
    }

    private function open_log($filename) {
        $this->file_pointer = fopen($filename, 'r');
        if ($this->file_pointer) {
            return true;
        } else {
            return false;
        }
    }

    private function close_log() {
        return fclose($this->file_pointer);
    }

    private function read_line() {
        return fgets($this->file_pointer);
    }

    private function parse_line($rawline) {
        $line = $this->parse_raw_line($rawline);
        if (isset($line[0])) {
            $parsed_line = array(
                'host' => $line[1],
                'identity' => $line[2],
                'user' => $line[3],
                'date' => $line[4],
                'time' => $line[5],
                'timezone' => $line[6],
                'method' => $line[7],
                'path' => $line[8],
                'protocol' => $line[9],
                'status' => $line[10],
                'size' => $line[11],
                'referer' => $line[12],
                'agent' => $line[13]
            );
            return $parsed_line;
        } else {
            $this->bad_lines++;
            return false;
        }

    }

    private function parse_raw_line($rawline) {
        preg_match("/^(\S+) (\S+) (\S+) \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\S+) (\S+) (\".*?\") (\".*?\")$/", $rawline, $matches);
        return $matches;
    }

}

?>